import { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import { Grid, Stack, Typography } from '@mui/material';
import { OpenInNewOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import Drawer from '@components/common/drawer/Drawer';
import { PATH_INDICATOR, PATH_SECURITY_PLATFORM } from '@components/common/routes/paths';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { DeploymentStatusChip, RequestStatusChip, ValidationStatusChip } from './DisseminationStatusChips';
import { isHttpUrl, TEST_KINDS } from './disseminationAssuranceUtils';
import type { IocValidationRequestDetailsQuery } from './__generated__/IocValidationRequestDetailsQuery.graphql';

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
        platform_id
        reason
      }
      deployments {
        id
        deployment_status
        validation_status
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

const Field = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <Stack gap={0.5}>
    <Typography variant="h4">{label}</Typography>
    <div>{children}</div>
  </Stack>
);

const IocValidationRequestDetailsContent = ({ requestId }: { requestId: string }) => {
  const { t_i18n, nsdt, n } = useFormatter();
  const { iocValidationRequest: request } = useLazyLoadQuery<IocValidationRequestDetailsQuery>(
    iocValidationRequestDetailsQuery,
    { id: requestId },
    { fetchPolicy: 'store-and-network' },
  );
  if (!request) {
    return <Typography>{t_i18n('This validation request is not available')}</Typography>;
  }
  const summary = request.results_summary;
  const testKindLabel = (kind: string) => {
    const definition = TEST_KINDS.find((d) => d.kind === kind);
    return definition ? t_i18n(definition.label) : kind;
  };
  return (
    <Stack gap={3} data-testid="ioc-validation-request-details">
      <Grid container spacing={2}>
        <Grid item xs={6}>
          <Field label={t_i18n('Status')}><RequestStatusChip status={request.status} /></Field>
        </Grid>
        <Grid item xs={6}>
          <Field label={t_i18n('Requested by')}>{request.requested_by?.name ?? '-'}</Field>
        </Grid>
        <Grid item xs={6}>
          <Field label={t_i18n('Dispatched at')}>{nsdt(request.dispatched_at)}</Field>
        </Grid>
        <Grid item xs={6}>
          <Field label={t_i18n('Completed at')}>{nsdt(request.completed_at)}</Field>
        </Grid>
        <Grid item xs={12}>
          <Field label={t_i18n('Test kinds')}>{request.test_kinds.map(testKindLabel).join(', ')}</Field>
        </Grid>
        {request.status_message && (
          <Grid item xs={12}>
            <Field label={t_i18n('Message')}>{request.status_message}</Field>
          </Grid>
        )}
        {request.description && (
          <Grid item xs={12}>
            <Field label={t_i18n('Description')}>{request.description}</Field>
          </Grid>
        )}
      </Grid>
      <Card title={t_i18n('Results')}>
        <Grid container spacing={2}>
          {[
            { label: t_i18n('Tested pairs'), value: summary.total },
            { label: t_i18n('Detected'), value: summary.detected },
            { label: t_i18n('Prevented'), value: summary.prevented },
            { label: t_i18n('Missed'), value: summary.missed },
            { label: t_i18n('Error'), value: summary.error },
            { label: t_i18n('Skipped'), value: summary.skipped },
          ].map((item) => (
            <Grid item xs={4} key={item.label}>
              <Typography variant="body2" color="text.secondary">{item.label}</Typography>
              <Typography variant="h3" component="span">{n(item.value)}</Typography>
            </Grid>
          ))}
        </Grid>
      </Card>
      {isHttpUrl(request.external_uri) && (
        <Button
          variant="secondary"
          href={request.external_uri ?? undefined}
          target="_blank"
          rel="noopener noreferrer"
          startIcon={<OpenInNewOutlined fontSize="small" />}
        >
          {t_i18n('Open in OpenAEV')}
        </Button>
      )}
      <Card title={t_i18n('Deployments')}>
        <Stack gap={1}>
          {request.deployments.length === 0 && <Typography variant="body2">{t_i18n('No deployment readable with your access rights')}</Typography>}
          {request.deployments.map((deployment) => (
            <Stack key={deployment.id} direction="row" gap={1} alignItems="center" justifyContent="space-between">
              <Typography variant="body2" sx={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {deployment.from?.id ? <Link to={PATH_INDICATOR(deployment.from.id)}>{deployment.from.name}</Link> : t_i18n('Restricted')}
                {' / '}
                {deployment.to?.id ? <Link to={PATH_SECURITY_PLATFORM(deployment.to.id)}>{deployment.to.name}</Link> : t_i18n('Restricted')}
              </Typography>
              <DeploymentStatusChip status={deployment.deployment_status} />
              <ValidationStatusChip status={deployment.validation_status} />
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
                {` (${ioc.observable_type}, ${testKindLabel(ioc.test_kind)})`}
              </Typography>
            ))}
          </Stack>
        </Card>
      )}
      {request.skipped.length > 0 && (
        <Card title={t_i18n('Skipped')}>
          <Stack gap={0.5}>
            {request.skipped.map((skip) => (
              <Typography key={`${skip.indicator_id}-${skip.platform_id ?? 'all'}`} variant="body2">
                <Link to={PATH_INDICATOR(skip.indicator_id)}>{skip.indicator_id}</Link>
                {`: ${t_i18n(skip.reason)}`}
              </Typography>
            ))}
          </Stack>
        </Card>
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
