import React, { Suspense, useEffect, useRef, useState } from 'react';
import { graphql, useFragment, useLazyLoadQuery } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import Grid from '@mui/material/Grid';
import { useTheme } from '@mui/styles';
import { Link } from 'react-router';
import { Alert, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Spinner, Text } from '@filigran/design-system';
import { PATH_HUNT } from '../common/routes/paths';
import Button from '@common/button/Button';
import CodeBlock from '@components/common/CodeBlock';
import Card from '../../../components/common/card/Card';
import Loader, { LoaderVariant } from '../../../components/Loader';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { fetchQuery, MESSAGING$ } from '../../../relay/environment';
import Security from '../../../utils/Security';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { notifyPayloadErrors } from './hunt-mutation-utils';
import { HuntCodeEditorField, prismLanguageOf } from './HuntCodeEditor';
import { SIGMA_RULE_PLACEHOLDER } from './HuntCreation';
import HuntNativeQueriesField from './HuntNativeQueriesField';
import HuntSigmaValidation from './HuntSigmaValidation';
import { HuntRunStatusChip } from './HuntChips';
import { HUNT_PLATFORM_INTERNET, huntQueryLanguageLabel, huntRunFailure, isTerminalHuntRun, normalizeNativeQueries, type HuntNativeQueryFormValue } from './hunt-utils';
import { HuntLogic_hunt$key } from './__generated__/HuntLogic_hunt.graphql';
import { HuntLogicFieldPatchMutation } from './__generated__/HuntLogicFieldPatchMutation.graphql';
import { HuntLogicConnectorsQuery } from './__generated__/HuntLogicConnectorsQuery.graphql';
import { HuntLogicTestQueryMutation } from './__generated__/HuntLogicTestQueryMutation.graphql';
import { HuntLogicPreviewRunQuery, HuntLogicPreviewRunQuery$data } from './__generated__/HuntLogicPreviewRunQuery.graphql';

/** A translation preview is polled for at most this long before the page gives up waiting. */
export const HUNT_PREVIEW_POLL_INTERVAL_MS = 2000;
export const HUNT_PREVIEW_MAX_WAIT_MS = 60000;

const huntLogicFragment = graphql`
  fragment HuntLogic_hunt on Hunt {
    id
    hunt_type
    hunt_status
    sigma_rule
    native_queries {
      platform
      language
      query
      pipeline
    }
    scopePlatforms {
      id
    }
  }
`;

const huntLogicFieldPatchMutation = graphql`
  mutation HuntLogicFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    huntFieldPatch(id: $id, input: $input) {
      id
      ...HuntLogic_hunt
      ...HuntDetails_hunt
    }
  }
`;

const huntLogicConnectorsQuery = graphql`
  query HuntLogicConnectorsQuery {
    huntConnectors(onlyAlive: true) {
      id
      name
      platform
      supports_preview
      securityPlatform {
        id
        name
      }
    }
  }
`;

const huntLogicTestQueryMutation = graphql`
  mutation HuntLogicTestQueryMutation($id: ID!, $securityPlatformId: ID) {
    huntTestQuery(id: $id, securityPlatformId: $securityPlatformId) {
      id
      hunt_run_status
    }
  }
`;

const huntLogicPreviewRunQuery = graphql`
  query HuntLogicPreviewRunQuery($id: String!) {
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

type PreviewRun = NonNullable<HuntLogicPreviewRunQuery$data['huntRun']>;

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
    | { status: 'timeout' };

const ANY_PLATFORM = 'any';

interface TranslationPreviewProps {
  huntId: string;
  huntType: string;
  scopePlatformIds: string[];
  dirty: boolean;
}

const TranslationPreview = ({ huntId, huntType, scopePlatformIds, dirty }: TranslationPreviewProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { huntConnectors } = useLazyLoadQuery<HuntLogicConnectorsQuery>(huntLogicConnectorsQuery, {}, { fetchPolicy: 'store-and-network' });
  const [platformId, setPlatformId] = useState<string>(ANY_PLATFORM);
  const [preview, setPreview] = useState<PreviewState>({ status: 'idle' });
  const [commitTest] = useApiMutation<HuntLogicTestQueryMutation>(huntLogicTestQueryMutation);
  const pollTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => {
    if (pollTimer.current) clearTimeout(pollTimer.current);
  }, []);

  // The connectors the platform can pick, as the dispatch does: the internet platform for an infrastructure hunt,
  // the security platforms of the hunt scope (all of them for an unscoped hunt) otherwise
  const eligibleConnectors = huntConnectors.filter((connector) => connector.supports_preview && (huntType === 'infrastructure'
    ? connector.platform === HUNT_PLATFORM_INTERNET
    : connector.platform !== HUNT_PLATFORM_INTERNET && !!connector.securityPlatform && scopePlatformIds.includes(connector.securityPlatform.id)));
  const platforms = new Map<string, string>();
  eligibleConnectors.forEach((connector) => {
    if (connector.securityPlatform) {
      platforms.set(connector.securityPlatform.id, connector.securityPlatform.name);
    }
  });
  const hasPreviewConnector = eligibleConnectors.length > 0;

  const poll = (runId: string, startedAt: number) => {
    fetchQuery<HuntLogicPreviewRunQuery>(huntLogicPreviewRunQuery, { id: runId }, { fetchPolicy: 'network-only' })
      .toPromise()
      .then((data) => {
        const run = data?.huntRun;
        if (run && isTerminalHuntRun(run.hunt_run_status)) {
          setPreview({ status: 'done', run });
        } else if (Date.now() - startedAt >= HUNT_PREVIEW_MAX_WAIT_MS) {
          setPreview({ status: 'timeout' });
        } else {
          setPreview({ status: 'waiting', run: run ?? undefined });
          pollTimer.current = setTimeout(() => poll(runId, startedAt), HUNT_PREVIEW_POLL_INTERVAL_MS);
        }
      })
      .catch(() => setPreview({ status: 'timeout' }));
  };

  const start = () => {
    if (pollTimer.current) clearTimeout(pollTimer.current);
    setPreview({ status: 'waiting' });
    commitTest({
      variables: { id: huntId, securityPlatformId: platformId === ANY_PLATFORM ? null : platformId },
      onCompleted: (data, errors) => {
        if (!notifyPayloadErrors(errors) && data.huntTestQuery) {
          poll(data.huntTestQuery.id, Date.now());
        } else {
          setPreview({ status: 'idle' });
        }
      },
      onError: () => setPreview({ status: 'idle' }),
    });
  };

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
  } else if (preview.status === 'done') {
    const { run } = preview;
    content = (
      <>
        <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), marginBottom: theme.spacing(1) }}>
          <HuntRunStatusChip value={run.hunt_run_status} />
          <Text variant="content-caption">{[run.connector_name, huntQueryLanguageLabel(run.query_language, t_i18n)].filter(Boolean).join(' - ')}</Text>
        </div>
        <PreviewFailure run={run} />
        {run.translated_query && <CodeBlock code={run.translated_query} language={prismLanguageOf(run.query_language)} customHeight="auto" />}
      </>
    );
  }

  return (
    <div data-testid="hunt-translation-preview">
      {!hasPreviewConnector ? (
        <Text variant="content-compact">{t_i18n('No live hunt connector supports translation preview on the platforms of this hunt')}</Text>
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
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <Button variant="secondary" onClick={start} disabled={preview.status === 'waiting'} data-testid="hunt-translation-preview-start">
                {t_i18n('Preview the translation')}
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

interface LogicValues {
  sigma_rule: string;
  native_queries: HuntNativeQueryFormValue[];
}

interface HuntLogicProps {
  data: HuntLogic_hunt$key;
}

const HuntLogic = ({ data }: HuntLogicProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const canEdit = useGranted([KNOWLEDGE_KNUPDATE]);
  const hunt = useFragment(huntLogicFragment, data);
  const [commit] = useApiMutation<HuntLogicFieldPatchMutation>(huntLogicFieldPatchMutation);
  const isTelemetry = hunt.hunt_type !== 'infrastructure';
  const initialValues: LogicValues = {
    sigma_rule: hunt.sigma_rule ?? '',
    native_queries: (hunt.native_queries ?? []).map((nativeQuery) => ({
      platform: nativeQuery.platform,
      language: nativeQuery.language,
      query: nativeQuery.query,
      pipeline: nativeQuery.pipeline ?? '',
    })),
  };
  const validation = Yup.object().shape({
    native_queries: Yup.array().of(Yup.object().shape({
      platform: Yup.string().required(t_i18n('This field is required')),
      language: Yup.string().required(t_i18n('This field is required')),
      query: Yup.string().trim().required(t_i18n('This field is required')),
    })),
  });
  const onSubmit = (values: LogicValues, { setSubmitting, resetForm }: { setSubmitting: (submitting: boolean) => void; resetForm: (next: { values: LogicValues }) => void }) => {
    const input: { key: string; value: unknown[] }[] = [
      ...(isTelemetry ? [{ key: 'sigma_rule', value: [values.sigma_rule] }] : []),
      { key: 'native_queries', value: normalizeNativeQueries(values.native_queries) },
    ];
    commit({
      variables: { id: hunt.id, input },
      onCompleted: (_, errors) => {
        setSubmitting(false);
        if (notifyPayloadErrors(errors)) {
          return;
        }
        resetForm({ values });
        MESSAGING$.notifySuccess(t_i18n('The hunt logic has been saved'));
      },
      onError: () => setSubmitting(false),
    });
  };
  return (
    <Formik<LogicValues> initialValues={initialValues} validationSchema={validation} onSubmit={onSubmit} enableReinitialize>
      {({ values, dirty, isSubmitting, submitForm, resetForm }) => (
        <Form data-testid="hunt-logic-page">
          <Grid container spacing={3}>
            {isTelemetry && (
              <Grid item xs={12} lg={7}>
                <Card title={t_i18n('Sigma rule')}>
                  <Field
                    component={HuntCodeEditorField}
                    name="sigma_rule"
                    label={t_i18n('Sigma rule (YAML)')}
                    language="yaml"
                    placeholder={SIGMA_RULE_PLACEHOLDER}
                    minRows={14}
                    maxRows={40}
                    disabled={!canEdit}
                    testId="hunt-logic-sigma"
                  />
                  <HuntSigmaValidation sigmaRule={values.sigma_rule} />
                </Card>
              </Grid>
            )}
            <Grid item xs={12} lg={isTelemetry ? 5 : 12}>
              <Card title={t_i18n('Translation preview')}>
                <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
                  <TranslationPreview huntId={hunt.id} huntType={hunt.hunt_type} scopePlatformIds={(hunt.scopePlatforms ?? []).map((platform) => platform.id)} dirty={dirty} />
                </Suspense>
              </Card>
            </Grid>
            <Grid item xs={12}>
              <Card title={t_i18n('Native queries')}>
                <HuntNativeQueriesField disabled={!canEdit} />
              </Card>
            </Grid>
          </Grid>
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: theme.spacing(1), marginTop: theme.spacing(2) }}>
              <Button variant="secondary" onClick={() => resetForm()} disabled={!dirty || isSubmitting}>
                {t_i18n('Discard changes')}
              </Button>
              <Button onClick={submitForm} disabled={!dirty || isSubmitting} data-testid="hunt-logic-save">
                {t_i18n('Save the logic')}
              </Button>
            </div>
          </Security>
        </Form>
      )}
    </Formik>
  );
};

export default HuntLogic;
