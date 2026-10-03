import React, { Suspense, useEffect } from 'react';
import { graphql, useFragment, useLazyLoadQuery } from 'react-relay';
import { Link, useNavigate, useParams } from 'react-router';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import Grid from '@mui/material/Grid';
import { useTheme } from '@mui/styles';
import { AutoAwesomeOutlined, ReplayOutlined } from '@mui/icons-material';
import { Chip, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import EEChip from '@components/common/entreprise_edition/EEChip';
import CodeBlock from '@components/common/CodeBlock';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ItemIcon from '../../../../components/ItemIcon';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import SelectFieldFds, { SelectItem } from '../../../../components/fields/SelectFieldFds';
import TextareaField from '../../../../components/TextareaField';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { notifyPayloadErrors } from '../hunt-mutation-utils';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import { resolveLink } from '../../../../utils/Entity';
import { PATH_HUNT, PATH_INCIDENT, PATH_SECURITY_COVERAGE } from '../../common/routes/paths';
import { HuntRunStatusChip, HuntVerdictChip } from '../HuntChips';
import { prismLanguageOf } from '../HuntCodeEditor';
import useHuntAI from '../useHuntAI';
import {
  canRetryHuntRun,
  canSetHuntRunVerdict,
  canStartHuntRun,
  canTriageHuntRun,
  formatHuntRunDuration,
  HUNT_ANALYST_VERDICTS,
  huntDraftWorkspacePath,
  huntRunTriggerLabel,
  huntVerdictLabel,
  huntVerdictSourceLabel,
  isTerminalHuntRun,
} from '../hunt-utils';
import { shortHash } from '../hunt-evidence-utils';
import { insertStartedHuntRuns } from './hunt-run-store';
import { HuntRunDrawer_run$data, HuntRunDrawer_run$key } from './__generated__/HuntRunDrawer_run.graphql';
import { HuntRunDrawerQuery } from './__generated__/HuntRunDrawerQuery.graphql';
import { HuntRunDrawerVerdictMutation } from './__generated__/HuntRunDrawerVerdictMutation.graphql';
import { HuntRunDrawerRetryMutation } from './__generated__/HuntRunDrawerRetryMutation.graphql';
import { HuntRunDrawerTriageMutation } from './__generated__/HuntRunDrawerTriageMutation.graphql';

const RUN_POLL_INTERVAL_MS = 5000;

const huntRunDrawerFragment = graphql`
  fragment HuntRunDrawer_run on HuntRun {
    id
    hunt_id
    hunt {
      id
      name
      hunt_status
    }
    hunt_run_status
    hunt_run_trigger
    hunt_run_mode
    securityPlatform {
      id
      name
    }
    connector_id
    connector_name
    work_id
    time_window_start
    time_window_end
    translated_query
    query_language
    hits_count
    distinct_entities
    evidence_sample {
      field
      value_hash
      value_preview
      count
    }
    results(first: 50) {
      edges {
        node {
          ... on BasicObject {
            id
            entity_type
          }
          ... on StixObject {
            representative {
              main
            }
          }
          ... on StixRelationship {
            representative {
              main
            }
          }
        }
      }
    }
    verdict
    verdict_source
    verdict_rationale
    analyst_feedback
    verdict_proposal
    verdict_proposal_confidence
    verdict_proposal_rationale
    verdict_proposal_agent
    incident_proposal
    incident_id
    draft_id
    security_coverage_id
    technique_id
    triggeredBy {
      id
      name
    }
    attempt
    next_retry_at
    dispatched_at
    started_at
    completed_at
    cost_ms
    error_message
    playbook_id
    created_at
  }
`;

const huntRunDrawerQuery = graphql`
  query HuntRunDrawerQuery($id: String!) {
    huntRun(id: $id) {
      id
      hunt_id
      ...HuntRunDrawer_run
    }
  }
`;

const huntRunDrawerVerdictMutation = graphql`
  mutation HuntRunDrawerVerdictMutation($id: ID!, $input: HuntRunVerdictInput!) {
    huntRunSetVerdict(id: $id, input: $input) {
      id
      ...HuntRunDrawer_run
      ...HuntRuns_RunFragment
    }
  }
`;

const huntRunDrawerRetryMutation = graphql`
  mutation HuntRunDrawerRetryMutation($id: ID!) {
    huntRunRetry(id: $id) {
      id
      ...HuntRuns_RunFragment
    }
  }
`;

const huntRunDrawerTriageMutation = graphql`
  mutation HuntRunDrawerTriageMutation($id: ID!) {
    huntRunTriage(id: $id) {
      id
      ...HuntRunDrawer_run
    }
  }
`;

interface IncidentProposal {
  name?: string | null;
  description?: string | null;
  severity?: string | null;
}

/** The agent proposal of an incident is stored as JSON; an unreadable one is ignored. */
export const parseHuntIncidentProposal = (proposal?: string | null): IncidentProposal | null => {
  if (!proposal) return null;
  try {
    const parsed = JSON.parse(proposal);
    return typeof parsed === 'object' && parsed !== null ? parsed as IncidentProposal : null;
  } catch {
    return null;
  }
};

const severityOf = (severity?: string | null) => {
  switch (severity) {
    case 'critical': return 'critical' as const;
    case 'high': return 'high' as const;
    case 'medium': return 'medium' as const;
    case 'low': return 'low' as const;
    default: return 'neutral' as const;
  }
};

type Run = HuntRunDrawer_run$data;

const Field2 = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <>
    <Label sx={{ marginTop: 2 }}>{label}</Label>
    {children}
  </>
);

const RunDetails = ({ run }: { run: Run }) => {
  const { t_i18n, fldt, n } = useFormatter();
  const value = (content?: string | number | null) => <Text variant="content-compact">{content === null || content === undefined || content === '' ? '-' : content}</Text>;
  return (
    <Card title={t_i18n('Details')}>
      <Grid container spacing={2}>
        <Grid item xs={6}>
          <Label>{t_i18n('Status')}</Label>
          <HuntRunStatusChip value={run.hunt_run_status} />
          <Field2 label={t_i18n('Trigger')}>{value(t_i18n(huntRunTriggerLabel(run.hunt_run_trigger)))}</Field2>
          <Field2 label={t_i18n('Mode')}>{value(run.hunt_run_mode === 'preview' ? t_i18n('Translation preview') : t_i18n('Execution'))}</Field2>
          <Field2 label={t_i18n('Platform')}>{value(run.securityPlatform?.name ?? t_i18n('Internet'))}</Field2>
          <Field2 label={t_i18n('Connector')}>{value(run.connector_name)}</Field2>
          <Field2 label={t_i18n('Triggered by')}>{value(run.triggeredBy?.name)}</Field2>
          <Field2 label={t_i18n('Attempt')}>{value(run.attempt)}</Field2>
        </Grid>
        <Grid item xs={6}>
          <Label>{t_i18n('Time window')}</Label>
          {value(run.time_window_start && run.time_window_end ? `${fldt(run.time_window_start)} - ${fldt(run.time_window_end)}` : null)}
          <Field2 label={t_i18n('Dispatch date')}>{value(run.dispatched_at ? fldt(run.dispatched_at) : null)}</Field2>
          <Field2 label={t_i18n('Start date')}>{value(run.started_at ? fldt(run.started_at) : null)}</Field2>
          <Field2 label={t_i18n('Completion date')}>{value(run.completed_at ? fldt(run.completed_at) : null)}</Field2>
          <Field2 label={t_i18n('Duration')}>{value(formatHuntRunDuration(run.cost_ms))}</Field2>
          <Field2 label={t_i18n('Hits')}>{value(run.hits_count === null || run.hits_count === undefined ? null : n(run.hits_count))}</Field2>
          <Field2 label={t_i18n('Distinct entities')}>{value(run.distinct_entities === null || run.distinct_entities === undefined ? null : n(run.distinct_entities))}</Field2>
          {run.next_retry_at && <Field2 label={t_i18n('Next retry')}>{value(fldt(run.next_retry_at))}</Field2>}
        </Grid>
        {run.error_message && (
          <Grid item xs={12}>
            <Label>{t_i18n('Error')}</Label>
            <Text variant="content-compact" data-testid="hunt-run-error">{run.error_message}</Text>
          </Grid>
        )}
      </Grid>
    </Card>
  );
};

const RunEvidence = ({ run }: { run: Run }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();
  const evidence = [...(run.evidence_sample ?? [])].sort((a, b) => b.count - a.count);
  const results = (run.results?.edges ?? []).map((edge) => edge?.node).filter((node) => !!node?.id);
  const cellStyle: React.CSSProperties = { padding: theme.spacing(0.75, 1), borderBottom: `1px solid ${theme.palette.divider}`, textAlign: 'left', verticalAlign: 'top' };
  return (
    <Card title={t_i18n('Evidence and results')}>
      {evidence.length === 0 ? (
        <Text variant="content-compact">{t_i18n('No evidence was reported for this run')}</Text>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }} data-testid="hunt-run-evidence">
          <caption style={{ textAlign: 'left', marginBottom: theme.spacing(1) }}>
            <Text variant="content-caption">{t_i18n('Evidence values are hashed by the connector; only a preview is kept')}</Text>
          </caption>
          <thead>
            <tr>
              <th scope="col" style={cellStyle}>{t_i18n('Field')}</th>
              <th scope="col" style={cellStyle}>{t_i18n('Value')}</th>
              <th scope="col" style={cellStyle}>{t_i18n('Hash')}</th>
              <th scope="col" style={{ ...cellStyle, textAlign: 'right' }}>{t_i18n('Count')}</th>
            </tr>
          </thead>
          <tbody>
            {evidence.map((item) => (
              <tr key={`${item.field}::${item.value_hash}`}>
                <td style={cellStyle}>{item.field}</td>
                <td style={{ ...cellStyle, wordBreak: 'break-all' }}>{item.value_preview ?? '-'}</td>
                <td style={cellStyle} title={item.value_hash}>{shortHash(item.value_hash)}</td>
                <td style={{ ...cellStyle, textAlign: 'right' }}>{n(item.count)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {results.length > 0 && (
        <>
          <Label sx={{ marginTop: 2 }}>{t_i18n('Results')}</Label>
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }} data-testid="hunt-run-results">
            {results.map((result) => result && (
              <li key={result.id} style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), padding: theme.spacing(0.5, 0) }}>
                <ItemIcon type={result.entity_type} />
                <Link to={`${resolveLink(result.entity_type)}/${result.id}`}>
                  {result.representative?.main ?? result.id}
                </Link>
              </li>
            ))}
          </ul>
        </>
      )}
    </Card>
  );
};

interface VerdictValues {
  verdict: string;
  analyst_feedback: string;
}

const RunVerdict = ({ run }: { run: Run }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation<HuntRunDrawerVerdictMutation>(huntRunDrawerVerdictMutation);
  const editable = canSetHuntRunVerdict(run);
  const onSubmit = (values: VerdictValues, { setSubmitting }: { setSubmitting: (submitting: boolean) => void }) => {
    commit({
      variables: { id: run.id, input: { verdict: values.verdict as 'true_positive', analyst_feedback: values.analyst_feedback || null, source: 'analyst' } },
      onCompleted: (_, errors) => {
        setSubmitting(false);
        if (!notifyPayloadErrors(errors)) {
          MESSAGING$.notifySuccess(t_i18n('The verdict has been saved'));
        }
      },
      onError: () => setSubmitting(false),
    });
  };
  return (
    <Card title={t_i18n('Verdict')}>
      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
        <HuntVerdictChip value={run.verdict} />
        {run.verdict_source && <Text variant="content-caption">{t_i18n(huntVerdictSourceLabel(run.verdict_source))}</Text>}
      </div>
      {run.verdict_rationale && (
        <>
          <Label sx={{ marginTop: 2 }}>{t_i18n('Rationale')}</Label>
          <ExpandableMarkdown source={run.verdict_rationale} limit={300} />
        </>
      )}
      {run.analyst_feedback && (
        <>
          <Label sx={{ marginTop: 2 }}>{t_i18n('Analyst feedback')}</Label>
          <ExpandableMarkdown source={run.analyst_feedback} limit={300} />
        </>
      )}
      {editable && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <Formik<VerdictValues>
            initialValues={{ verdict: run.verdict === 'pending' ? 'true_positive' : run.verdict, analyst_feedback: '' }}
            validationSchema={Yup.object().shape({ verdict: Yup.string().oneOf([...HUNT_ANALYST_VERDICTS]).required(t_i18n('This field is required')) })}
            onSubmit={onSubmit}
          >
            {({ submitForm, isSubmitting }) => (
              <Form style={{ marginTop: theme.spacing(2) }} data-testid="hunt-run-verdict-form">
                <Field component={SelectFieldFds} name="verdict" label={t_i18n('Your verdict')} required>
                  {HUNT_ANALYST_VERDICTS.map((verdict) => (
                    <SelectItem key={verdict} value={verdict}>{t_i18n(huntVerdictLabel(verdict))}</SelectItem>
                  ))}
                </Field>
                <div style={{ marginTop: theme.spacing(2) }}>
                  <Field component={TextareaField} name="analyst_feedback" label={t_i18n('Feedback')} rows={3} />
                </div>
                <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(1) }}>
                  {t_i18n('A true positive verdict opens an incident in a draft for review')}
                </Text>
                <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: theme.spacing(2) }}>
                  <Button onClick={submitForm} disabled={isSubmitting} data-testid="hunt-run-verdict-submit">
                    {t_i18n('Save the verdict')}
                  </Button>
                </div>
              </Form>
            )}
          </Formik>
        </Security>
      )}
    </Card>
  );
};

const RunTriage = ({ run }: { run: Run }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { available, isEnterpriseEdition } = useHuntAI();
  const [commitTriage, triaging] = useApiMutation<HuntRunDrawerTriageMutation>(huntRunDrawerTriageMutation);
  const [commitVerdict, accepting] = useApiMutation<HuntRunDrawerVerdictMutation>(huntRunDrawerVerdictMutation);
  const incident = parseHuntIncidentProposal(run.incident_proposal);
  const canTriage = canTriageHuntRun(run);
  const hasProposal = !!run.verdict_proposal;
  const proposalApplied = hasProposal && run.verdict_source === 'agent' && run.verdict === run.verdict_proposal;
  const accept = () => {
    if (!run.verdict_proposal) return;
    commitVerdict({
      variables: { id: run.id, input: { verdict: run.verdict_proposal, source: 'agent' } },
      onCompleted: (_, errors) => {
        if (!notifyPayloadErrors(errors)) {
          MESSAGING$.notifySuccess(t_i18n('The proposed verdict has been applied'));
        }
      },
    });
  };
  let unavailableReason: string | null = null;
  if (!isEnterpriseEdition) {
    unavailableReason = t_i18n('AI triage is an Enterprise Edition capability');
  } else if (!available) {
    unavailableReason = t_i18n('AI triage needs XTM One to be configured on the platform');
  }
  return (
    <Card
      title={(
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: theme.spacing(1) }}>
          {t_i18n('AI triage')}
          <EEChip />
        </span>
      )}
    >
      <div data-testid="hunt-run-triage">
        {unavailableReason && <Text variant="content-compact">{unavailableReason}</Text>}
        {!unavailableReason && !hasProposal && (
          <Text variant="content-compact">
            {canTriage ? t_i18n('Ask an agent to propose a verdict for this run; the proposal is never applied without you') : t_i18n('Only completed runs can be triaged')}
          </Text>
        )}
        {hasProposal && (
          <>
            <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
              <Text variant="content-compact-bold">{t_i18n('Proposed verdict')}</Text>
              <HuntVerdictChip value={run.verdict_proposal} />
              <Text variant="content-compact" data-testid="hunt-run-triage-confidence">
                {run.verdict_proposal_confidence === null || run.verdict_proposal_confidence === undefined
                  ? t_i18n('Confidence not assessed')
                  : t_i18n('Confidence {value}%', { values: { value: run.verdict_proposal_confidence } })}
              </Text>
              {run.verdict_proposal_agent && <Text variant="content-caption">{t_i18n('by {agent}', { values: { agent: run.verdict_proposal_agent } })}</Text>}
            </div>
            {run.verdict_proposal_rationale && (
              <>
                <Label sx={{ marginTop: 2 }}>{t_i18n('Rationale')}</Label>
                <ExpandableMarkdown source={run.verdict_proposal_rationale} limit={400} />
              </>
            )}
            {incident && (
              <>
                <Label sx={{ marginTop: 2 }}>{t_i18n('Proposed incident')}</Label>
                <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
                  <Text variant="content-compact-bold">{incident.name ?? '-'}</Text>
                  {incident.severity && <Chip label={incident.severity} severity={severityOf(incident.severity)} />}
                </div>
                {incident.description && <ExpandableMarkdown source={incident.description} limit={300} />}
              </>
            )}
          </>
        )}
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <div style={{ display: 'flex', gap: theme.spacing(1), justifyContent: 'flex-end', marginTop: theme.spacing(2) }}>
            {hasProposal && canSetHuntRunVerdict(run) && !proposalApplied && (
              <Button variant="secondary" onClick={accept} disabled={accepting} data-testid="hunt-run-triage-accept">
                {t_i18n('Accept the proposal')}
              </Button>
            )}
            <Button
              intent="ai"
              variant={hasProposal ? 'tertiary' : 'secondary'}
              startIcon={<AutoAwesomeOutlined fontSize="small" />}
              disabled={!!unavailableReason || !canTriage || triaging}
              onClick={() => commitTriage({ variables: { id: run.id } })}
              data-testid="hunt-run-triage-start"
            >
              {hasProposal ? t_i18n('Triage again') : t_i18n('Triage with AI')}
            </Button>
          </div>
        </Security>
      </div>
    </Card>
  );
};

const RunLinks = ({ run }: { run: Run }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const links: { key: string; to: string; label: string }[] = [];
  if (run.draft_id) {
    links.push({ key: 'draft', to: huntDraftWorkspacePath(run.draft_id), label: t_i18n('Open the incident draft') });
  }
  if (run.incident_id && !run.draft_id) {
    links.push({ key: 'incident', to: PATH_INCIDENT(run.incident_id), label: t_i18n('Open the incident') });
  }
  if (run.connector_id) {
    links.push({ key: 'work', to: `/dashboard/data/ingestion/connectors/${run.connector_id}`, label: run.work_id ? t_i18n('Open the connector work') : t_i18n('Open the connector') });
  }
  if (run.playbook_id) {
    links.push({ key: 'playbook', to: `/dashboard/data/processing/automation/${run.playbook_id}`, label: t_i18n('Open the playbook') });
  }
  if (run.security_coverage_id) {
    links.push({ key: 'coverage', to: PATH_SECURITY_COVERAGE(run.security_coverage_id), label: t_i18n('Open the security coverage') });
  }
  if (links.length === 0) {
    return null;
  }
  return (
    <Card title={t_i18n('Related')}>
      <ul style={{ margin: 0, paddingLeft: theme.spacing(2) }} data-testid="hunt-run-links">
        {links.map((link) => (
          <li key={link.key} style={{ padding: theme.spacing(0.25, 0) }}>
            <Link to={link.to}>{link.label}</Link>
          </li>
        ))}
      </ul>
      {run.draft_id && (
        <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(1) }}>
          {t_i18n('The incident stays in its draft until an analyst validates it into the knowledge graph')}
        </Text>
      )}
    </Card>
  );
};

const HuntRunDrawerContent = ({ data, huntId, paginationOptions }: { data: HuntRunDrawer_run$key; huntId: string; paginationOptions?: Record<string, unknown> }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const draftContext = useDraftContext();
  const run = useFragment(huntRunDrawerFragment, data);
  const [commitRetry, retrying] = useApiMutation<HuntRunDrawerRetryMutation>(huntRunDrawerRetryMutation);
  const terminal = isTerminalHuntRun(run.hunt_run_status);

  useEffect(() => {
    if (terminal) return undefined;
    const timer = setInterval(() => {
      fetchQuery(huntRunDrawerQuery, { id: run.id }).toPromise().catch(() => undefined);
    }, RUN_POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [run.id, terminal]);

  const retry = () => {
    commitRetry({
      variables: { id: run.id },
      updater: (store) => {
        if (paginationOptions) {
          insertStartedHuntRuns(store, [store.getRootField('huntRunRetry')], paginationOptions);
        }
      },
      onCompleted: (response, errors) => {
        if (!notifyPayloadErrors(errors) && response.huntRunRetry) {
          navigate(`${PATH_HUNT(huntId)}/runs/${response.huntRunRetry.id}`);
        }
      },
    });
  };
  const canRetry = canRetryHuntRun(run) && canStartHuntRun(run.hunt?.hunt_status, !!draftContext);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }} data-testid="hunt-run-drawer">
      {canRetry && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <Button variant="secondary" size="small" startIcon={<ReplayOutlined fontSize="small" />} onClick={retry} disabled={retrying} data-testid="hunt-run-retry">
              {t_i18n('Retry')}
            </Button>
          </div>
        </Security>
      )}
      <RunDetails run={run} />
      {run.translated_query && (
        <Card title={t_i18n('Translated query')}>
          <Text variant="content-caption" style={{ display: 'block', marginBottom: theme.spacing(1) }}>{run.query_language ?? ''}</Text>
          <CodeBlock code={run.translated_query} language={prismLanguageOf(run.query_language)} customHeight="auto" />
        </Card>
      )}
      {run.hunt_run_mode !== 'preview' && (
        <>
          <RunEvidence run={run} />
          <RunVerdict run={run} />
          <RunTriage run={run} />
        </>
      )}
      <RunLinks run={run} />
    </div>
  );
};

const HuntRunDrawerLoader = ({ runId, huntId, paginationOptions }: { runId: string; huntId: string; paginationOptions?: Record<string, unknown> }) => {
  const { t_i18n } = useFormatter();
  const { huntRun } = useLazyLoadQuery<HuntRunDrawerQuery>(huntRunDrawerQuery, { id: runId }, { fetchPolicy: 'store-and-network' });
  if (!huntRun || huntRun.hunt_id !== huntId) {
    return <Text variant="content-compact">{t_i18n('This run cannot be found')}</Text>;
  }
  return <HuntRunDrawerContent data={huntRun} huntId={huntId} paginationOptions={paginationOptions} />;
};

interface HuntRunDrawerProps {
  huntId: string;
  paginationOptions?: Record<string, unknown>;
}

const HuntRunDrawer = ({ huntId, paginationOptions }: HuntRunDrawerProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const { runId } = useParams() as { runId: string };
  return (
    <Drawer
      title={t_i18n('Hunt run')}
      open
      onClose={() => navigate(`${PATH_HUNT(huntId)}/runs`)}
      size="large"
    >
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <HuntRunDrawerLoader runId={runId} huntId={huntId} paginationOptions={paginationOptions} />
      </Suspense>
    </Drawer>
  );
};

export default HuntRunDrawer;
