import { ReactNode, Suspense, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import { Grid, Stack, Typography } from '@mui/material';
import { OpenInNewOutlined, ReplayOutlined } from '@mui/icons-material';
import { Alert, ProgressBar, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import Drawer from '@components/common/drawer/Drawer';
import { PATH_INDICATOR, PATH_SECURITY_PLATFORM } from '@components/common/routes/paths';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Security from '../../../../utils/Security';
import useGranted, { KNOWLEDGE_KNUPDATE, MODULES_MODMANAGE } from '../../../../utils/hooks/useGranted';
import { DeploymentStatusChip, RequestStatusChip, ValidationStatusChip } from './DisseminationStatusChips';
import IocValidationRequestDialog from './IocValidationRequestDialog';
import { isHttpUrl, isOpenRequest, TEST_KINDS } from './disseminationAssuranceUtils';
import type { IocValidationRequestDetailsQuery, IocValidationRequestDetailsQuery$data } from './__generated__/IocValidationRequestDetailsQuery.graphql';

const iocValidationRequestDetailsQuery = graphql`
  query IocValidationRequestDetailsQuery($id: String!) {
    iocValidationRequest(id: $id) {
      id
      name
      description
      status
      status_message
      test_kinds
      indicators_count
      external_uri
      created_at
      dispatched_at
      completed_at
      requested_by {
        id
        name
      }
      platforms {
        id
        name
      }
      results_summary {
        total
        requested
        detected
        prevented
        missed
        error
        skipped
      }
      iocs {
        indicator_id
        observable_type
        value
        test_kind
      }
      skipped {
        indicator_id
        indicator {
          id
          name
        }
        platform_id
        reason
      }
      pair_outcomes {
        deployed_on_id
        validation_status
      }
      deployments {
        id
        deployment_status
        last_validation_at
        from {
          ... on Indicator {
            id
            name
          }
        }
        to {
          ... on SecurityPlatform {
            id
            name
          }
        }
      }
    }
  }
`;

type IocValidationRequestData = NonNullable<IocValidationRequestDetailsQuery$data['iocValidationRequest']>;

const Field = ({ label, children }: { label: string; children: ReactNode }) => (
  <Stack gap={0.5}>
    <Typography variant="h4">{label}</Typography>
    <div>{children}</div>
  </Stack>
);

const useStatusSentence = () => {
  const { t_i18n } = useFormatter();
  return (request: IocValidationRequestData) => {
    const { total, detected, prevented, error } = request.results_summary;
    switch (request.status) {
      case 'pending':
        return t_i18n('Waiting for an active OpenAEV IOC validation connector');
      case 'sent':
        return t_i18n('Sent to OpenAEV, waiting for it to be received');
      case 'awaiting_approval':
        return t_i18n('Waiting for approval in OpenAEV');
      case 'running':
        return t_i18n('{count, plural, one {Running on # platform} other {Running on # platforms}}', { values: { count: request.platforms.length } });
      case 'completed':
        return t_i18n('Completed - {count} of {total} detected or prevented', { values: { count: detected + prevented, total } });
      case 'partial':
        return t_i18n(
          'Partially completed - {count} of {total} detected or prevented, {error, plural, one {# test could not run} other {# tests could not run}}',
          { values: { count: detected + prevented, total, error } },
        );
      case 'rejected':
        return t_i18n('Rejected in OpenAEV, nothing was tested');
      case 'expired':
        return t_i18n('OpenAEV did not answer before the timeout, the waiting tests are marked as errors');
      default:
        return t_i18n('The validation could not run, the waiting tests are marked as errors');
    }
  };
};

export const OPENAEV_IOC_VALIDATION_DOCUMENTATION_URL = 'https://docs.openaev.io/latest/usage/build/scenario/ioc-validation/';
// Start of the status message of a request whose connector account cannot report results (back end, plain words).
const MISSING_CAPABILITIES_MESSAGE = 'The account of the OpenAEV IOC validation connector needs';

/** What to do while a request waits for the OpenAEV IOC validation connector: set it up, or ask who can. */
const PendingNextStep = ({ statusMessage }: { statusMessage: string | null | undefined }) => {
  const { t_i18n } = useFormatter();
  const canManageConnectors = useGranted([MODULES_MODMANAGE]);
  const missingCapabilities = !!statusMessage?.startsWith(MISSING_CAPABILITIES_MESSAGE);
  let description: string;
  if (missingCapabilities) {
    description = canManageConnectors
      ? t_i18n('Give the OpenCTI account of the connector the Connector role, with the Update knowledge and Connectors API usage capabilities.')
      : t_i18n('Ask your administrator to give the OpenCTI account of the connector the Connector role.');
  } else {
    description = canManageConnectors
      ? t_i18n('Configure OpenCTI in OpenAEV, then check that its IOC validation connector is running.')
      : t_i18n('Ask an administrator to configure OpenCTI in OpenAEV and start its IOC validation connector.');
  }
  return (
    <Alert
      severity="warning"
      data-testid="ioc-validation-pending-next-step"
      title={missingCapabilities ? t_i18n('The OpenAEV IOC validation connector cannot report results') : t_i18n('No OpenAEV IOC validation connector is active')}
      description={missingCapabilities && statusMessage ? `${statusMessage}. ${description}` : description}
      action={(
        <Stack direction="row" gap={1}>
          {canManageConnectors && (
            <Button variant="secondary" size="small" component={Link} to="/dashboard/integrations">
              {t_i18n('Open connector settings')}
            </Button>
          )}
          <Button variant="tertiary" size="small" href={OPENAEV_IOC_VALIDATION_DOCUMENTATION_URL} target="_blank" rel="noopener noreferrer">
            {t_i18n('Read the documentation')}
          </Button>
        </Stack>
      )}
    />
  );
};

const IocValidationRequestDetailsContent = ({ requestId }: { requestId: string }) => {
  const { t_i18n, nsdt, rd, n } = useFormatter();
  const statusSentence = useStatusSentence();
  const [validateAgain, setValidateAgain] = useState(false);
  const { iocValidationRequest: request } = useLazyLoadQuery<IocValidationRequestDetailsQuery>(
    iocValidationRequestDetailsQuery,
    { id: requestId },
    { fetchPolicy: 'store-and-network' },
  );
  if (!request) {
    return <Typography>{t_i18n('This validation request is not available')}</Typography>;
  }
  const summary = request.results_summary;
  const proven = summary.detected + summary.prevented;
  const testKindLabel = (kind: string) => {
    const definition = TEST_KINDS.find((d) => d.kind === kind);
    return definition ? t_i18n(definition.label) : kind;
  };
  const openInOpenAev = isHttpUrl(request.external_uri) && isOpenRequest(request.status);
  // The verdict of this request: a newer request on the same deployment does not change it
  const outcomes = new Map(request.pair_outcomes.map((outcome) => [outcome.deployed_on_id, outcome.validation_status]));
  const indicators = new Map<string, string>();
  request.deployments.forEach((deployment) => {
    if (deployment.from?.id) indicators.set(deployment.from.id, deployment.from.name ?? deployment.from.id);
  });
  const primaryAction = openInOpenAev ? (
    <Button
      href={request.external_uri ?? undefined}
      target="_blank"
      rel="noopener noreferrer"
      startIcon={<OpenInNewOutlined fontSize="small" />}
    >
      {t_i18n('Open in OpenAEV')}
    </Button>
  ) : (!isOpenRequest(request.status) && indicators.size > 0 && (
    <Security needs={[KNOWLEDGE_KNUPDATE]}>
      <Button startIcon={<ReplayOutlined fontSize="small" />} onClick={() => setValidateAgain(true)} data-testid="ioc-validation-validate-again">
        {t_i18n('Validate again')}
      </Button>
    </Security>
  ));
  return (
    <Stack gap={3} data-testid="ioc-validation-request-details">
      <Stack direction="row" alignItems="flex-start" justifyContent="space-between" gap={2} data-testid="ioc-validation-status-header">
        <Stack gap={0.5} sx={{ minWidth: 0 }}>
          <Stack direction="row" alignItems="center" gap={1}>
            <RequestStatusChip status={request.status} />
            <Typography variant="body1">{statusSentence(request)}</Typography>
          </Stack>
          <Tooltip>
            <TooltipTrigger asChild>
              <Typography variant="caption" color="text.secondary">
                {t_i18n('Requested {date}', { values: { date: rd(request.created_at) } })}
              </Typography>
            </TooltipTrigger>
            <TooltipContent>{nsdt(request.created_at)}</TooltipContent>
          </Tooltip>
          {request.status_message && !['completed', 'awaiting_approval', 'running', 'pending'].includes(request.status) && (
            <Typography variant="caption" color="text.secondary">{request.status_message}</Typography>
          )}
        </Stack>
        {primaryAction}
      </Stack>
      {request.status === 'pending' && <PendingNextStep statusMessage={request.status_message} />}
      <Grid container spacing={2}>
        {request.requested_by && (
          <Grid item xs={6}>
            <Field label={t_i18n('Requested by')}>{request.requested_by.name}</Field>
          </Grid>
        )}
        {request.dispatched_at && (
          <Grid item xs={6}>
            <Field label={t_i18n('Dispatched at')}>{nsdt(request.dispatched_at)}</Field>
          </Grid>
        )}
        {request.completed_at && (
          <Grid item xs={6}>
            <Field label={t_i18n('Completed at')}>{nsdt(request.completed_at)}</Field>
          </Grid>
        )}
        <Grid item xs={12}>
          <Field label={t_i18n('Test kinds')}>{request.test_kinds.map(testKindLabel).join(', ')}</Field>
        </Grid>
        {request.description && (
          <Grid item xs={12}>
            <Field label={t_i18n('Description')}>{request.description}</Field>
          </Grid>
        )}
      </Grid>
      <Card title={t_i18n('Results')}>
        <Stack gap={2}>
          <Stack gap={1}>
            <Typography variant="body1" id={`ioc-validation-results-${request.id}`} data-testid="ioc-validation-results-summary">
              {t_i18n('{count} of {total, plural, one {# test} other {# tests}} detected or prevented', { values: { count: proven, total: summary.total } })}
            </Typography>
            <ProgressBar
              value={summary.total > 0 ? Math.round((proven / summary.total) * 100) : 0}
              tone={summary.missed > 0 ? 'error' : 'success'}
              aria-labelledby={`ioc-validation-results-${request.id}`}
            />
          </Stack>
          <Grid container spacing={2}>
            {[
              { label: t_i18n('Detected'), value: summary.detected },
              { label: t_i18n('Prevented'), value: summary.prevented },
              { label: t_i18n('Missed'), value: summary.missed },
              { label: t_i18n('Error'), value: summary.error },
              { label: t_i18n('Waiting'), value: summary.requested },
              { label: t_i18n('Skipped'), value: summary.skipped },
            ].map((item) => (
              <Grid item xs={4} key={item.label}>
                <Typography variant="body2" color="text.secondary">{item.label}</Typography>
                <Typography variant="h3" component="span">{n(item.value)}</Typography>
              </Grid>
            ))}
          </Grid>
        </Stack>
      </Card>
      <Card title={t_i18n('Deployments')}>
        <Stack gap={1}>
          {request.deployments.length === 0 && <Typography variant="body2">{t_i18n('No deployment readable with your access rights')}</Typography>}
          {request.deployments.map((deployment) => (
            <Stack key={deployment.id} direction="row" gap={1} alignItems="center" justifyContent="space-between">
              <ItemIcon type="Indicator" size="small" />
              <Typography variant="body2" sx={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {deployment.from?.id ? <Link to={PATH_INDICATOR(deployment.from.id)}>{deployment.from.name}</Link> : t_i18n('Restricted')}
                {' / '}
                {deployment.to?.id ? <Link to={PATH_SECURITY_PLATFORM(deployment.to.id)}>{deployment.to.name}</Link> : t_i18n('Restricted')}
              </Typography>
              <DeploymentStatusChip status={deployment.deployment_status} />
              <ValidationStatusChip status={outcomes.get(deployment.id)} />
              {outcomes.get(deployment.id) === 'missed' && deployment.from?.id && (
                <Button variant="tertiary" size="small" component={Link} to={`${PATH_INDICATOR(deployment.from.id)}/deployments`}>
                  {t_i18n('Open the deployment')}
                </Button>
              )}
            </Stack>
          ))}
        </Stack>
      </Card>
      {request.iocs.length > 0 && (
        <Card title={t_i18n('Tested values')}>
          <Stack gap={0.5}>
            {request.iocs.map((ioc) => (
              <Typography key={`${ioc.indicator_id}-${ioc.test_kind}-${ioc.value}`} variant="body2" sx={{ wordBreak: 'break-all' }}>
                <code>{ioc.value}</code>
                {' - '}
                {testKindLabel(ioc.test_kind)}
              </Typography>
            ))}
          </Stack>
        </Card>
      )}
      {request.skipped.length > 0 && (
        <Card title={t_i18n('Skipped')}>
          <Stack gap={1}>
            {request.skipped.map((skip) => (
              <Stack key={`${skip.indicator_id}-${skip.platform_id ?? 'all'}`} direction="row" alignItems="flex-start" gap={1}>
                <ItemIcon type="Indicator" size="small" />
                <Stack sx={{ minWidth: 0 }}>
                  <Typography variant="body2" noWrap>
                    <Link to={PATH_INDICATOR(skip.indicator_id)}>{skip.indicator?.name ?? t_i18n('Restricted')}</Link>
                  </Typography>
                  <Typography variant="caption" color="text.secondary">{t_i18n(skip.reason)}</Typography>
                </Stack>
              </Stack>
            ))}
          </Stack>
        </Card>
      )}
      {validateAgain && (
        <IocValidationRequestDialog
          open
          onClose={() => setValidateAgain(false)}
          indicators={[...indicators.entries()].map(([id, name]) => ({ id, name }))}
          platforms={request.platforms.map((platform) => ({ id: platform.id, name: platform.name }))}
          defaultName={request.name}
        />
      )}
    </Stack>
  );
};

interface IocValidationRequestDetailsProps {
  requestId: string | null;
  title: string;
  onClose: () => void;
}

const IocValidationRequestDetails = ({ requestId, title, onClose }: IocValidationRequestDetailsProps) => (
  <Drawer title={title} open={!!requestId} onClose={onClose} size="medium">
    {requestId ? (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <IocValidationRequestDetailsContent requestId={requestId} />
      </Suspense>
    ) : null}
  </Drawer>
);

export default IocValidationRequestDetails;
