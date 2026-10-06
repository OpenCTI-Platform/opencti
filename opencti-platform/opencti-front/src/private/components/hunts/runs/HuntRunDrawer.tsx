import React, { Suspense, useEffect, useRef, useState } from 'react';
import { graphql, useFragment, useLazyLoadQuery } from 'react-relay';
import { Link, useNavigate, useParams } from 'react-router';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import Grid from '@mui/material/Grid';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import { useTheme } from '@mui/styles';
import { AutoAwesomeOutlined, ExpandLessOutlined, ExpandMoreOutlined, ReplayOutlined, WarningAmberOutlined } from '@mui/icons-material';
import { Alert, Chip, Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import EEChip from '@components/common/entreprise_edition/EEChip';
import CodeBlock from '@components/common/CodeBlock';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import SelectFieldFds, { SelectItem } from '../../../../components/fields/SelectFieldFds';
import SwitchField from '../../../../components/fields/SwitchField';
import TextareaField from '../../../../components/TextareaField';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { notifyPayloadErrors } from '../hunt-mutation-utils';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
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
  HUNT_DOCS,
  huntDraftWorkspacePath,
  huntIncidentSeverityLabel,
  huntMessageText,
  huntQueryLanguageLabel,
  huntRunFailure,
  huntRunHitsBreakdown,
  huntRunPartialResultsSentence,
  huntRunTriggerLabel,
  huntRunUnresolvedTechniquesSentence,
  huntVerdictLabel,
  huntVerdictOffersIncident,
  huntVerdictSourceLabel,
  isTerminalHuntRun,
} from '../hunt-utils';
import { HuntLearnMore } from '../HuntLearnMore';
import { shortHash } from '../hunt-evidence-utils';
import { insertStartedHuntRuns } from './hunt-run-store';
import HuntRunResults from './HuntRunResults';
import HuntRunIocResults from './HuntRunIocResults';
import HuntRunHits from './HuntRunHits';
import { HuntRunResults_data$key } from './__generated__/HuntRunResults_data.graphql';
import { HuntRunDrawer_run$data, HuntRunDrawer_run$key } from './__generated__/HuntRunDrawer_run.graphql';
import { HuntRunDrawerQuery } from './__generated__/HuntRunDrawerQuery.graphql';
import { HuntRunDrawerVerdictMutation } from './__generated__/HuntRunDrawerVerdictMutation.graphql';
import { HuntRunDrawerRetryMutation } from './__generated__/HuntRunDrawerRetryMutation.graphql';
import { HuntRunDrawerTriageMutation } from './__generated__/HuntRunDrawerTriageMutation.graphql';

const RUN_POLL_INTERVAL_MS = 5000;

const huntRunDrawerFragment = graphql`
  fragment HuntRunDrawer_run on HuntRun {
    id
    ...HuntRunIocResults_run
    hunt_id
    hunt {
      id
      name
      hunt_status
      hunt_max_results
    }
    hunt_run_status
    hunt_run_trigger
    hunt_run_mode
    queue_reason {
      template
      values {
        name
        value
      }
    }
    unresolved_techniques
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
    hits_new_count
    hits_recurring_count
    hits_identified
    time_window_continued
    incident_continued
    hits_sample {
      event_id
      timestamp
      host
      user
      process
      matched {
        field
        value_preview
      }
      is_new
      times_seen
      known_since
    }
    results_truncated
    distinct_entities
    evidence_sample {
      field
      value_hash
      value_preview
      count
    }
    verdict
    verdict_source
    verdict_rationale
    hunt_analyst_feedback
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
    ...HuntRunResults_data @arguments(id: $id)
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

const runPlatformName = (run: Run, t_i18n: (message: string) => string) => run.securityPlatform?.name ?? run.connector_name ?? t_i18n('Internet');

/** A date shown relative to now, the absolute date in its tooltip. */
const RelativeDate = ({ date }: { date: string }) => {
  const { fldt, rd } = useFormatter();
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0}>{rd(date)}</span>
      </TooltipTrigger>
      <TooltipContent>{fldt(date)}</TooltipContent>
    </Tooltip>
  );
};

interface DetailRow {
  key: string;
  label: string;
  value: React.ReactNode;
}

/** Rows without a value are left out rather than shown as a dash. */
const DetailGrid = ({ rows, testId }: { rows: DetailRow[]; testId: string }) => (
  <Grid container spacing={2} data-testid={testId}>
    {rows.filter((row) => row.value !== null && row.value !== undefined && row.value !== '').map((row) => (
      <Grid item xs={6} key={row.key}>
        <Label>{row.label}</Label>
        <Text variant="content-compact">{row.value}</Text>
      </Grid>
    ))}
  </Grid>
);

const Disclosure = ({ label, openLabel, testId, children }: { label: string; openLabel: string; testId: string; children: React.ReactNode }) => {
  const theme = useTheme<Theme>();
  const [open, setOpen] = useState(false);
  return (
    <>
      <div style={{ marginTop: theme.spacing(1) }}>
        <Button
          variant="tertiary"
          size="small"
          aria-expanded={open}
          startIcon={open ? <ExpandLessOutlined fontSize="small" /> : <ExpandMoreOutlined fontSize="small" />}
          onClick={() => setOpen(!open)}
          data-testid={testId}
        >
          {open ? openLabel : label}
        </Button>
      </div>
      {open && children}
    </>
  );
};

const RunDetails = ({ run }: { run: Run }) => {
  const { t_i18n, fldt, n } = useFormatter();
  const count = (value?: number | null) => (value === null || value === undefined ? null : n(value));
  const date = (value?: string | null) => (value ? <RelativeDate date={value} /> : null);
  const essentials: DetailRow[] = [
    { key: 'platform', label: t_i18n('Platform'), value: runPlatformName(run, t_i18n) },
    { key: 'connector', label: t_i18n('Connector'), value: run.connector_name },
    { key: 'trigger', label: t_i18n('Trigger'), value: t_i18n(huntRunTriggerLabel(run.hunt_run_trigger)) },
    { key: 'triggered_by', label: t_i18n('Triggered by'), value: run.triggeredBy?.name },
    { key: 'started', label: t_i18n('Started'), value: date(run.started_at) },
    { key: 'duration', label: t_i18n('Duration'), value: formatHuntRunDuration(run.cost_ms) },
    {
      key: 'hits',
      label: t_i18n('Hits'),
      // Partial results: the platform did not return everything, the count is a lower bound
      value: run.results_truncated
        ? t_i18n('At least {count}', { values: { count: n(run.hits_count ?? 0) } })
        : huntRunHitsBreakdown(run, t_i18n, n) ?? count(run.hits_count),
    },
    { key: 'distinct_entities', label: t_i18n('Distinct entities'), value: count(run.distinct_entities) },
  ];
  const more: DetailRow[] = [
    { key: 'mode', label: t_i18n('Mode'), value: run.hunt_run_mode === 'preview' ? t_i18n('Translation preview') : t_i18n('Execution') },
    {
      key: 'time_window',
      label: t_i18n('Time window'),
      value: run.time_window_start && run.time_window_end ? `${fldt(run.time_window_start)} - ${fldt(run.time_window_end)}` : null,
    },
    { key: 'dispatched', label: t_i18n('Dispatched'), value: date(run.dispatched_at) },
    { key: 'completed', label: t_i18n('Completed'), value: date(run.completed_at) },
    { key: 'attempt', label: t_i18n('Attempt'), value: count(run.attempt) },
    { key: 'next_retry', label: t_i18n('Next retry'), value: date(run.next_retry_at) },
  ];
  return (
    <Card title={t_i18n('Details')}>
      <DetailGrid rows={essentials} testId="hunt-run-details" />
      <Disclosure label={t_i18n('Show more details')} openLabel={t_i18n('Hide the details')} testId="hunt-run-more-details-toggle">
        <div style={{ marginTop: 8 }}>
          <DetailGrid rows={more} testId="hunt-run-more-details" />
        </div>
      </Disclosure>
    </Card>
  );
};

/** What failed, why, and the next action, instead of the raw error the connector reported. */
// Retry is the primary action of the status header: the alert carries the fix of the failure class
const RunFailureAlert = ({ run, huntId }: { run: Run; huntId: string }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [showDetails, setShowDetails] = useState(false);
  const failure = huntRunFailure(run.hunt_run_status, run.error_message);
  if (!failure) {
    return null;
  }
  const platform = runPlatformName(run, t_i18n);
  const checkConnector = run.connector_id ? (
    <Button variant="secondary" size="small" component={Link} to={`/dashboard/data/ingestion/connectors/${run.connector_id}`} data-testid="hunt-run-check-connector">
      {t_i18n('Check the connector')}
    </Button>
  ) : undefined;
  let title: string;
  let action: React.ReactNode;
  switch (failure.kind) {
    case 'timeout':
      title = failure.timeoutSeconds
        ? t_i18n('The connector did not answer within {timeout}', { values: { timeout: formatHuntRunDuration(failure.timeoutSeconds * 1000) } })
        : t_i18n('The connector did not answer in time');
      action = checkConnector;
      break;
    case 'translation':
      title = t_i18n('The Sigma rule could not be translated for {platform}', { values: { platform } });
      action = (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <Button variant="secondary" size="small" component={Link} to={`${PATH_HUNT(huntId)}/logic`} data-testid="hunt-run-edit-rule">
            {t_i18n('Edit the rule')}
          </Button>
        </Security>
      );
      break;
    case 'access':
      // The sentence of the connector names the missing permission, as its connection test does
      title = t_i18n('Access denied on {platform}', { values: { platform } });
      action = run.connector_id ? (
        <Button variant="secondary" size="small" component={Link} to={`/dashboard/data/ingestion/connectors/${run.connector_id}`} data-testid="hunt-run-test-connection">
          {t_i18n('Test the connection of the connector')}
        </Button>
      ) : undefined;
      break;
    case 'refused':
    case 'request':
      title = failure.kind === 'refused'
        ? t_i18n('{platform} refused the query', { values: { platform } })
        : t_i18n('The hunt connector could not read the run sent by the platform');
      action = checkConnector;
      break;
    default:
      title = t_i18n('The run failed in {platform}', { values: { platform } });
      action = checkConnector;
  }
  return (
    <Alert
      severity="error"
      title={title}
      action={action}
      data-testid="hunt-run-failure"
      data-kind={failure.kind}
      description={failure.kind === 'access' && run.error_message ? (
        <Text variant="content-caption" style={{ display: 'block', wordBreak: 'break-word' }} data-testid="hunt-run-error">
          {run.error_message.replace(/^HuntAccessDeniedError:\s*/, '')}
        </Text>
      ) : run.error_message ? (
        <>
          <Button variant="tertiary" size="small" aria-expanded={showDetails} onClick={() => setShowDetails(!showDetails)} data-testid="hunt-run-failure-details-toggle">
            {showDetails ? t_i18n('Hide details') : t_i18n('Show details')}
          </Button>
          {showDetails && (
            <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(0.5), wordBreak: 'break-word' }} data-testid="hunt-run-error">
              {run.error_message}
            </Text>
          )}
        </>
      ) : undefined}
    />
  );
};

const RunEvidence = ({ run, results }: { run: Run; results: HuntRunResults_data$key }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();
  const evidence = [...(run.evidence_sample ?? [])].sort((a, b) => b.count - a.count);
  return (
    <Card title={t_i18n('Evidence and results')} action={<HuntLearnMore href={HUNT_DOCS.runs} />}>
      {evidence.length === 0 ? (
        <Text variant="content-compact">{t_i18n('No evidence was reported for this run')}</Text>
      ) : (
        <>
          <Text variant="content-caption" style={{ display: 'block', marginBottom: theme.spacing(1) }}>
            {t_i18n('OpenCTI hashes and masks the evidence values it receives before storing them; only a masked preview is kept')}
          </Text>
          <TableContainer style={{ maxHeight: 360 }}>
            <Table size="small" stickyHeader aria-label={t_i18n('Evidence and results')} data-testid="hunt-run-evidence">
              <TableHead>
                <TableRow>
                  <TableCell>{t_i18n('Field')}</TableCell>
                  <TableCell>{t_i18n('Value')}</TableCell>
                  <TableCell>{t_i18n('Hash')}</TableCell>
                  <TableCell align="right">{t_i18n('Count')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {evidence.map((item) => (
                  <TableRow key={`${item.field}::${item.value_hash}`}>
                    <TableCell>{item.field}</TableCell>
                    <TableCell style={{ wordBreak: 'break-all' }}>{item.value_preview ?? t_i18n('No preview')}</TableCell>
                    <TableCell title={item.value_hash}>{shortHash(item.value_hash)}</TableCell>
                    <TableCell align="right">{n(item.count)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </>
      )}
      <HuntRunResults data={results} />
    </Card>
  );
};

interface VerdictValues {
  verdict: string;
  hunt_analyst_feedback: string;
  create_incident: boolean;
}

const RunVerdict = ({ run, cardRef }: { run: Run; cardRef: React.RefObject<HTMLDivElement | null> }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation<HuntRunDrawerVerdictMutation>(huntRunDrawerVerdictMutation);
  const editable = canSetHuntRunVerdict(run);
  const onSubmit = (values: VerdictValues, { setSubmitting }: { setSubmitting: (submitting: boolean) => void }) => {
    commit({
      variables: {
        id: run.id,
        input: {
          verdict: values.verdict as 'true_positive',
          hunt_analyst_feedback: values.hunt_analyst_feedback || null,
          source: 'analyst',
          create_incident: huntVerdictOffersIncident(values.verdict, run) ? values.create_incident : null,
        },
      },
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
    <div ref={cardRef} data-testid="hunt-run-verdict">
      <Card title={t_i18n('Verdict')} action={<HuntLearnMore href={HUNT_DOCS.runs} testId="hunt-run-verdict-learn-more" />}>
        <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
          <HuntVerdictChip value={run.verdict} />
          <Text variant="content-caption">{t_i18n(huntVerdictSourceLabel(run.verdict_source))}</Text>
        </div>
        <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(1), color: theme.palette.text.secondary }}>
          {t_i18n('True positive: the hypothesis is confirmed. Benign: the results are legitimate activity, or the run searched everything without a hit. Inconclusive: the run cannot prove either way, for example with partial results or values not searched. Pending: no verdict yet.')}
        </Text>
        {run.verdict_rationale && (
          <>
            <Label sx={{ marginTop: 2 }}>{t_i18n('Rationale')}</Label>
            <ExpandableMarkdown source={run.verdict_rationale} limit={300} />
          </>
        )}
        {run.hunt_analyst_feedback && (
          <>
            <Label sx={{ marginTop: 2 }}>{t_i18n('Analyst feedback')}</Label>
            <ExpandableMarkdown source={run.hunt_analyst_feedback} limit={300} />
          </>
        )}
        {editable && (
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <Formik<VerdictValues>
              initialValues={{ verdict: run.verdict === 'pending' ? 'true_positive' : run.verdict, hunt_analyst_feedback: '', create_incident: true }}
              validationSchema={Yup.object().shape({ verdict: Yup.string().oneOf([...HUNT_ANALYST_VERDICTS]).required(t_i18n('This field is required')) })}
              onSubmit={onSubmit}
            >
              {({ submitForm, isSubmitting, values }) => (
                <Form style={{ marginTop: theme.spacing(2) }} data-testid="hunt-run-verdict-form">
                  <Field component={SelectFieldFds} name="verdict" label={t_i18n('Your verdict')} required>
                    {HUNT_ANALYST_VERDICTS.map((verdict) => (
                      <SelectItem key={verdict} value={verdict}>{t_i18n(huntVerdictLabel(verdict))}</SelectItem>
                    ))}
                  </Field>
                  <div style={{ marginTop: theme.spacing(2) }}>
                    <Field component={TextareaField} name="hunt_analyst_feedback" label={t_i18n('Feedback')} rows={3} />
                  </div>
                  {huntVerdictOffersIncident(values.verdict, run) && (
                    <div style={{ marginTop: theme.spacing(2) }} data-testid="hunt-run-verdict-incident">
                      <Field
                        component={SwitchField}
                        type="checkbox"
                        name="create_incident"
                        label={t_i18n('Escalate to an incident')}
                        helpertext={values.create_incident
                          ? t_i18n('The hits go to the open incident of this hunt, or to a new incident draft')
                          : t_i18n('Only the verdict is recorded')}
                      />
                    </div>
                  )}
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
        {(canTriageHuntRun(run) || !!run.verdict_proposal) && <RunTriage run={run} />}
      </Card>
    </div>
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
    <section style={{ marginTop: theme.spacing(3), paddingTop: theme.spacing(2), borderTop: `1px solid ${theme.palette.divider}` }}>
      <div style={{ display: 'inline-flex', alignItems: 'center', gap: theme.spacing(1), marginBottom: theme.spacing(1) }}>
        <Text variant="content-compact-bold">{t_i18n('AI triage')}</Text>
        <EEChip />
      </div>
      <div data-testid="hunt-run-triage">
        {unavailableReason && <Text variant="content-compact">{unavailableReason}</Text>}
        {!unavailableReason && !hasProposal && (
          <Text variant="content-compact">
            {t_i18n('Ask an agent to propose a verdict for this run; the proposal is never applied without you')}
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
                  {incident.severity && <Chip label={t_i18n(huntIncidentSeverityLabel(incident.severity))} severity={severityOf(incident.severity)} />}
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
              onClick={() => commitTriage({
                variables: { id: run.id },
                onCompleted: (_, errors) => {
                  notifyPayloadErrors(errors);
                },
              })}
              data-testid="hunt-run-triage-start"
            >
              {hasProposal ? t_i18n('Triage again') : t_i18n('Triage with AI')}
            </Button>
          </div>
        </Security>
      </div>
    </section>
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
      {run.incident_continued && (
        <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(1) }} data-testid="hunt-run-incident-continued">
          {t_i18n('The new hits of this run went to the incident still open from a previous run')}
        </Text>
      )}
      {run.draft_id && (
        <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(1) }}>
          {t_i18n('The incident stays in its draft until an analyst validates it into the knowledge graph')}
        </Text>
      )}
    </Card>
  );
};

/** Why the hit count of a run with partial results is a lower bound, and how to get complete results next time. */
const RunPartialResultsAlert = ({ run, huntId }: { run: Run; huntId: string }) => {
  const { t_i18n, n } = useFormatter();
  const navigate = useNavigate();
  const title = huntRunPartialResultsSentence(
    { hits_count: run.hits_count, maxResults: run.hunt?.hunt_max_results },
    runPlatformName(run, t_i18n),
    t_i18n,
    n,
  );
  return (
    <Alert
      severity="warning"
      title={title}
      description={t_i18n('Matches may be missing from this run, and a run without hits in partial results proves nothing: narrow the time window or the scope of the hunt so that its runs fit in what the platform returns.')}
      data-testid="hunt-run-partial-results"
      action={(
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <Button
            variant="secondary"
            size="small"
            onClick={() => navigate(PATH_HUNT(huntId), { state: { openHuntEdition: true } })}
            data-testid="hunt-run-narrow-hunt"
          >
            {t_i18n('Narrow the hunt')}
          </Button>
        </Security>
      )}
    />
  );
};

interface RunStatusHeaderProps {
  run: Run;
  huntId: string;
  canRetry: boolean;
  retrying: boolean;
  onRetry: () => void;
  onSetVerdict: () => void;
}

/** Where the run stands in one sentence, with the next action: the first thing the drawer answers. */
const RunStatusHeader = ({ run, huntId, canRetry, retrying, onRetry, onSetVerdict }: RunStatusHeaderProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n, rd } = useFormatter();
  const terminal = isTerminalHuntRun(run.hunt_run_status);
  const [, setNow] = useState(Date.now());
  useEffect(() => {
    if (terminal) return undefined;
    const timer = setInterval(() => setNow(Date.now()), 15000);
    return () => clearInterval(timer);
  }, [terminal]);
  const platform = runPlatformName(run, t_i18n);
  const failure = huntRunFailure(run.hunt_run_status, run.error_message);
  const isExecution = run.hunt_run_mode !== 'preview';
  let sentence: string | null = null;
  if (run.hunt_run_status === 'completed' && !isExecution) {
    sentence = t_i18n('The translation for {platform} is ready', { values: { platform } });
  } else if (run.hunt_run_status === 'completed') {
    const hits = run.hits_count ?? 0;
    const entities = run.distinct_entities ?? 0;
    const values = {
      hits: hits === 1 ? t_i18n('1 hit') : t_i18n('{count} hits', { values: { count: n(hits) } }),
      entities: entities === 1 ? t_i18n('1 entity') : t_i18n('{count} entities', { values: { count: n(entities) } }),
      platform,
    };
    if (run.results_truncated) {
      sentence = run.verdict === 'pending'
        ? t_i18n('{hits} on {entities} in {platform} - partial results, verdict pending', { values })
        : t_i18n('{hits} on {entities} in {platform} - partial results', { values });
    } else {
      sentence = run.verdict === 'pending'
        ? t_i18n('{hits} on {entities} in {platform} - verdict pending', { values })
        : t_i18n('{hits} on {entities} in {platform}', { values });
    }
  } else if (run.hunt_run_status === 'running') {
    const since = run.started_at ?? run.dispatched_at ?? run.created_at;
    const elapsed = formatHuntRunDuration(Math.max(0, Date.now() - new Date(since).getTime()));
    sentence = t_i18n('Running in {platform} for {duration}', { values: { platform, duration: elapsed } });
  } else if (run.hunt_run_status === 'queued') {
    sentence = t_i18n('Queued {when}', { values: { when: rd(run.created_at) } });
  } else if (run.hunt_run_status === 'cancelled') {
    // The platform records why it cancelled the run as one of its sentences, the translation key of the reason
    sentence = run.error_message ? t_i18n(run.error_message) : t_i18n('The run was cancelled');
  }
  let primary: React.ReactNode = null;
  if (isExecution && run.verdict === 'pending' && canSetHuntRunVerdict(run)) {
    primary = (
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <Button onClick={onSetVerdict} data-testid="hunt-run-set-verdict">{t_i18n('Set the verdict')}</Button>
      </Security>
    );
  } else if (failure && canRetry) {
    // The failure alert below carries the fix of its class (check the connector, edit the rule)
    primary = (
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <Button startIcon={<ReplayOutlined fontSize="small" />} onClick={onRetry} disabled={retrying} data-testid="hunt-run-retry">
          {t_i18n('Retry')}
        </Button>
      </Security>
    );
  } else if (run.verdict === 'true_positive' && (run.draft_id || run.incident_id)) {
    const incidentPath = run.draft_id ? huntDraftWorkspacePath(run.draft_id) : PATH_INCIDENT(run.incident_id as string);
    primary = (
      <Button component={Link} to={incidentPath} data-testid="hunt-run-open-incident">
        {run.draft_id ? t_i18n('Open the incident draft') : t_i18n('Open the incident')}
      </Button>
    );
  }
  return (
    <Card aria-label={t_i18n('Run status')}>
      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }} data-testid="hunt-run-status-header">
        <HuntRunStatusChip value={run.hunt_run_status} />
        {isExecution && <HuntVerdictChip value={run.verdict} />}
        <div style={{ flex: 1 }} />
        {primary}
      </div>
      {sentence && (
        <Text variant="content-compact" style={{ display: 'block', marginTop: theme.spacing(1) }} data-testid="hunt-run-status-sentence">
          {sentence}
        </Text>
      )}
      {run.queue_reason && (
        <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(0.5), color: theme.palette.text.secondary }} data-testid="hunt-run-queue-reason">
          {huntMessageText(run.queue_reason, t_i18n)}
        </Text>
      )}
      {isExecution && run.unresolved_techniques.length > 0 && (
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: theme.spacing(1), marginTop: theme.spacing(1) }} data-testid="hunt-run-unresolved-techniques">
          <WarningAmberOutlined fontSize="small" style={{ color: theme.palette.warn.main }} aria-hidden />
          <Text variant="content-compact">{huntRunUnresolvedTechniquesSentence(run.unresolved_techniques, t_i18n)}</Text>
        </div>
      )}
      {failure && (
        <div style={{ marginTop: theme.spacing(1.5) }}>
          <RunFailureAlert run={run} huntId={huntId} />
        </div>
      )}
      {isExecution && run.hunt_run_status === 'completed' && run.results_truncated && (
        <div style={{ marginTop: theme.spacing(1.5) }}>
          <RunPartialResultsAlert run={run} huntId={huntId} />
        </div>
      )}
    </Card>
  );
};

interface HuntRunDrawerContentProps {
  data: HuntRunDrawer_run$key;
  results: HuntRunResults_data$key;
  huntId: string;
  paginationOptions?: Record<string, unknown>;
}

const HuntRunDrawerContent = ({ data, results, huntId, paginationOptions }: HuntRunDrawerContentProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const draftContext = useDraftContext();
  const run = useFragment(huntRunDrawerFragment, data);
  const [commitRetry, retrying] = useApiMutation<HuntRunDrawerRetryMutation>(huntRunDrawerRetryMutation);
  const terminal = isTerminalHuntRun(run.hunt_run_status);
  const verdictRef = useRef<HTMLDivElement>(null);
  const focusVerdict = () => {
    verdictRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    verdictRef.current?.querySelector<HTMLElement>('[data-testid="hunt-run-verdict-form"] button, [data-testid="hunt-run-verdict-form"] textarea')?.focus();
  };

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
  const isExecution = run.hunt_run_mode !== 'preview';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }} data-testid="hunt-run-drawer">
      <RunStatusHeader run={run} huntId={huntId} canRetry={canRetry} retrying={retrying} onRetry={retry} onSetVerdict={focusVerdict} />
      {isExecution && <RunVerdict run={run} cardRef={verdictRef} />}
      {isExecution && run.hunt_run_status === 'completed' && ((run.hits_count ?? 0) > 0 || run.time_window_continued) && (
        <HuntRunHits
          hitsCount={run.hits_count}
          newCount={run.hits_new_count}
          recurringCount={run.hits_recurring_count}
          identified={run.hits_identified}
          windowContinued={run.time_window_continued}
          platform={runPlatformName(run, t_i18n)}
          hits={run.hits_sample ?? []}
        />
      )}
      {isExecution && <HuntRunIocResults data={run} />}
      {isExecution && <RunEvidence run={run} results={results} />}
      <RunLinks run={run} />
      <RunDetails run={run} />
      {run.translated_query && (
        <Card title={t_i18n('Translated query')}>
          <Disclosure label={t_i18n('Show the query')} openLabel={t_i18n('Hide the query')} testId="hunt-run-query-toggle">
            <Text variant="content-caption" style={{ display: 'block', margin: theme.spacing(1, 0) }}>{huntQueryLanguageLabel(run.query_language, t_i18n)}</Text>
            <CodeBlock code={run.translated_query} language={prismLanguageOf(run.query_language)} customHeight="auto" />
          </Disclosure>
        </Card>
      )}
    </div>
  );
};

const HuntRunDrawerLoader = ({ runId, huntId, paginationOptions }: { runId: string; huntId: string; paginationOptions?: Record<string, unknown> }) => {
  const { t_i18n } = useFormatter();
  const data = useLazyLoadQuery<HuntRunDrawerQuery>(huntRunDrawerQuery, { id: runId }, { fetchPolicy: 'store-and-network' });
  const { huntRun } = data;
  if (!huntRun || huntRun.hunt_id !== huntId) {
    return <Text variant="content-compact">{t_i18n('This run cannot be found')}</Text>;
  }
  return <HuntRunDrawerContent data={huntRun} results={data} huntId={huntId} paginationOptions={paginationOptions} />;
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
