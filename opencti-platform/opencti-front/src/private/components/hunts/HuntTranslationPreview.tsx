import React, { useEffect, useRef, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useTheme } from '@mui/styles';
import { Link } from 'react-router';
import { Alert, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Spinner, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import CodeBlock from '@components/common/CodeBlock';
import { PATH_HUNT } from '../common/routes/paths';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { fetchQuery } from '../../../relay/environment';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { mutationErrorMessage, payloadErrorsMessage, useDialogMutation } from './hunt-mutation-utils';
import { prismLanguageOf } from './HuntCodeEditor';
import { HuntRunStatusChip } from './HuntChips';
import { huntQueryLanguageLabel, huntRunFailure, isHuntPreviewConnector, isTerminalHuntRun } from './hunt-utils';
import { HuntTranslationPreviewConnectorsQuery } from './__generated__/HuntTranslationPreviewConnectorsQuery.graphql';
import { HuntTranslationPreviewTestQueryMutation } from './__generated__/HuntTranslationPreviewTestQueryMutation.graphql';
import { HuntTranslationPreviewRunQuery, HuntTranslationPreviewRunQuery$data } from './__generated__/HuntTranslationPreviewRunQuery.graphql';

/** A translation preview is polled for at most this long before the page gives up waiting. */
export const HUNT_PREVIEW_POLL_INTERVAL_MS = 2000;
export const HUNT_PREVIEW_MAX_WAIT_MS = 60000;

const huntTranslationPreviewConnectorsQuery = graphql`
  query HuntTranslationPreviewConnectorsQuery {
    huntConnectors(onlyAlive: true) {
      id
      name
      platform
      supports_preview
      supports_indicators
      securityPlatform {
        id
        name
      }
    }
  }
`;

const huntTranslationPreviewTestQueryMutation = graphql`
  mutation HuntTranslationPreviewTestQueryMutation($id: ID!, $securityPlatformId: ID) {
    huntTestQuery(id: $id, securityPlatformId: $securityPlatformId) {
      id
      hunt_run_status
    }
  }
`;

const huntTranslationPreviewRunQuery = graphql`
  query HuntTranslationPreviewRunQuery($id: String!) {
    huntRun(id: $id) {
      id
      hunt_run_status
      translated_query
      query_language
      connector_name
      error_message
      securityPlatform {
        name
      }
    }
  }
`;

type PreviewRun = NonNullable<HuntTranslationPreviewRunQuery$data['huntRun']>;

const PreviewFailure = ({ run }: { run: PreviewRun }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [showDetails, setShowDetails] = useState(false);
  const failure = huntRunFailure(run.hunt_run_status, run.error_message);
  if (!failure) return null;
  const platform = run.securityPlatform?.name ?? run.connector_name ?? t_i18n('Internet');
  let title: string;
  switch (failure.kind) {
    case 'timeout':
      title = t_i18n('The connector did not answer in time');
      break;
    case 'translation':
      title = t_i18n('The Sigma rule could not be translated for {platform}', { values: { platform } });
      break;
    case 'refused':
      title = t_i18n('{platform} refused the query', { values: { platform } });
      break;
    case 'request':
      title = t_i18n('The hunt connector could not read the run sent by the platform');
      break;
    default:
      title = t_i18n('The run failed in {platform}', { values: { platform } });
  }
  return (
    <Alert
      severity="error"
      title={title}
      data-testid="hunt-preview-failure"
      description={run.error_message ? (
        <>
          <Button variant="tertiary" size="small" aria-expanded={showDetails} onClick={() => setShowDetails(!showDetails)}>
            {showDetails ? t_i18n('Hide details') : t_i18n('Show details')}
          </Button>
          {showDetails && (
            <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(0.5), wordBreak: 'break-word' }}>
              {run.error_message}
            </Text>
          )}
        </>
      ) : undefined}
    />
  );
};

type PreviewState
  = | { status: 'idle' }
    | { status: 'waiting'; run?: PreviewRun }
    | { status: 'done'; run: PreviewRun }
    | { status: 'timeout' }
    | { status: 'error'; message: string };

const ANY_PLATFORM = 'any';

interface HuntTranslationPreviewProps {
  huntId: string;
  huntType: string;
  scopePlatformIds: string[];
  /** The edited logic is not saved: the preview runs the saved one */
  dirty?: boolean;
  /** Starts the preview on the first available platform as soon as it renders */
  autoStart?: boolean;
  /** Starts the preview each time it increases, for instance once a generated rule is saved */
  startSignal?: number;
  /** Whether the user may change the hunt, which starting a preview needs, as the hunt page computes it */
  canStart?: boolean;
}

/** The query a hunt connector would run for the saved logic of a hunt, translated by the connector without executing it. */
const HuntTranslationPreview = ({ huntId, huntType, scopePlatformIds, dirty = false, autoStart = false, startSignal = 0, canStart = true }: HuntTranslationPreviewProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { huntConnectors } = useLazyLoadQuery<HuntTranslationPreviewConnectorsQuery>(huntTranslationPreviewConnectorsQuery, {}, { fetchPolicy: 'store-and-network' });
  const [platformId, setPlatformId] = useState<string>(ANY_PLATFORM);
  const [preview, setPreview] = useState<PreviewState>({ status: 'idle' });
  const [commitTest] = useDialogMutation<HuntTranslationPreviewTestQueryMutation>(huntTranslationPreviewTestQueryMutation);
  const pollTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const autoStarted = useRef(false);
  // An answer for an unmounted preview, or for a preview a newer one replaced, is ignored: it never updates the state
  // nor schedules another poll
  const mounted = useRef(false);
  const generation = useRef(0);
  const isCurrent = (token: number) => mounted.current && token === generation.current;
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      if (pollTimer.current) clearTimeout(pollTimer.current);
    };
  }, []);

  const eligibleConnectors = huntConnectors.filter((connector) => isHuntPreviewConnector(connector, huntType, scopePlatformIds));
  const platforms = new Map<string, string>();
  eligibleConnectors.forEach((connector) => {
    if (connector.securityPlatform) {
      platforms.set(connector.securityPlatform.id, connector.securityPlatform.name);
    }
  });
  const hasPreviewConnector = eligibleConnectors.length > 0;

  const poll = (runId: string, startedAt: number, token: number) => {
    fetchQuery<HuntTranslationPreviewRunQuery>(huntTranslationPreviewRunQuery, { id: runId }, { fetchPolicy: 'network-only' })
      .toPromise()
      .then((data) => {
        if (!isCurrent(token)) return;
        const run = data?.huntRun;
        if (run && isTerminalHuntRun(run.hunt_run_status)) {
          setPreview({ status: 'done', run });
        } else if (Date.now() - startedAt >= HUNT_PREVIEW_MAX_WAIT_MS) {
          setPreview({ status: 'timeout' });
        } else {
          setPreview({ status: 'waiting', run: run ?? undefined });
          pollTimer.current = setTimeout(() => poll(runId, startedAt, token), HUNT_PREVIEW_POLL_INTERVAL_MS);
        }
      })
      .catch(() => {
        if (isCurrent(token)) setPreview({ status: 'timeout' });
      });
  };

  const start = () => {
    if (pollTimer.current) clearTimeout(pollTimer.current);
    generation.current += 1;
    const token = generation.current;
    setPreview({ status: 'waiting' });
    commitTest({
      variables: { id: huntId, securityPlatformId: platformId === ANY_PLATFORM ? null : platformId },
      onCompleted: (data, errors) => {
        if (!isCurrent(token)) return;
        const errorMessage = payloadErrorsMessage(errors);
        if (errorMessage || !data.huntTestQuery) {
          setPreview({ status: 'error', message: errorMessage ?? t_i18n('The query preview could not be started') });
          return;
        }
        poll(data.huntTestQuery.id, Date.now(), token);
      },
      onError: (error) => {
        if (isCurrent(token)) setPreview({ status: 'error', message: mutationErrorMessage(error, t_i18n('The query preview could not be started')) });
      },
    });
  };

  useEffect(() => {
    if (autoStart && hasPreviewConnector && !autoStarted.current) {
      autoStarted.current = true;
      start();
    }
  }, [autoStart, hasPreviewConnector]);

  useEffect(() => {
    if (startSignal > 0 && hasPreviewConnector) {
      start();
    }
  }, [startSignal]);

  let content: React.ReactNode = null;
  if (preview.status === 'waiting') {
    content = <Spinner size="md" label={t_i18n('Waiting for the connector to translate the query')} />;
  } else if (preview.status === 'timeout') {
    content = (
      <Alert
        severity="warning"
        title={t_i18n('The connector did not answer in time')}
        description={t_i18n('The preview appears in the Runs tab once it completes')}
        action={(
          <Button variant="secondary" size="small" component={Link} to={`${PATH_HUNT(huntId)}/runs`} data-testid="hunt-preview-open-runs">
            {t_i18n('Open the runs')}
          </Button>
        )}
        data-testid="hunt-preview-timeout"
      />
    );
  } else if (preview.status === 'error') {
    content = (
      <Alert
        severity="error"
        title={t_i18n('The query preview could not be started')}
        description={preview.message}
        data-testid="hunt-preview-error"
      />
    );
  } else if (preview.status === 'done') {
    const { run } = preview;
    content = (
      <>
        <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), marginBottom: theme.spacing(1) }}>
          <HuntRunStatusChip value={run.hunt_run_status} />
          <Text variant="content-caption">{[run.connector_name, huntQueryLanguageLabel(run.query_language, t_i18n)].filter(Boolean).join(' - ')}</Text>
        </div>
        <PreviewFailure run={run} />
        {run.hunt_run_status === 'cancelled' && (
          <Text variant="content-compact" style={{ display: 'block' }} data-testid="hunt-preview-cancelled">
            {run.error_message ? t_i18n(run.error_message) : t_i18n('The run was cancelled')}
          </Text>
        )}
        {run.translated_query && <CodeBlock code={run.translated_query} language={prismLanguageOf(run.query_language)} customHeight="auto" />}
      </>
    );
  }

  const noConnectorSentence = huntType === 'indicators'
    ? t_i18n('No live hunt connector that looks up indicators serves the platforms of this hunt')
    : t_i18n('No live hunt connector supports translation preview on the platforms of this hunt');

  return (
    <div data-testid="hunt-translation-preview">
      {!hasPreviewConnector ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
          <Text variant="content-compact">{noConnectorSentence}</Text>
          <Button variant="tertiary" size="small" component={Link} to="/dashboard/data/ingestion/connectors">
            {t_i18n('Open the hunt connectors')}
          </Button>
        </div>
      ) : (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
            <Select value={platformId} onValueChange={setPlatformId}>
              <SelectTrigger aria-label={t_i18n('Platform of the preview')} style={{ minWidth: 240 }}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent aria-label={t_i18n('Platform of the preview')}>
                <SelectItem value={ANY_PLATFORM}>{t_i18n('First available platform')}</SelectItem>
                {Array.from(platforms.entries()).map(([id, name]) => (
                  <SelectItem key={id} value={id}>{name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Security needs={[KNOWLEDGE_KNUPDATE]} hasAccess={canStart}>
              <Button variant="secondary" onClick={start} disabled={preview.status === 'waiting'} data-testid="hunt-translation-preview-start">
                {t_i18n('Preview the query')}
              </Button>
            </Security>
          </div>
          {dirty && (
            <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(1) }}>
              {t_i18n('The preview uses the saved logic; save your changes first')}
            </Text>
          )}
          <div role="status" aria-live="polite" style={{ marginTop: theme.spacing(2) }}>
            {content}
          </div>
        </>
      )}
    </div>
  );
};

export default HuntTranslationPreview;
