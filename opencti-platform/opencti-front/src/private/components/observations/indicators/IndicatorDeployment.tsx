import { graphql, useFragment } from 'react-relay';
import { Grid, Stack, Typography } from '@mui/material';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import DeployedOnRelationships from '../../data/dissemination_assurance/DeployedOnRelationships';
import DisseminationAssuranceLink from '../../data/dissemination_assurance/DisseminationAssuranceLink';
import LiveDeploymentsValidationButton from '../../data/dissemination_assurance/LiveDeploymentsValidationButton';
import type { IndicatorDeployment_indicator$key } from './__generated__/IndicatorDeployment_indicator.graphql';

const indicatorDeploymentFragment = graphql`
  fragment IndicatorDeployment_indicator on Indicator {
    id
    name
    deployment_platforms_count
    deployment_failed_count
    validated_platforms_count
    hit_platforms_count
  }
`;

const Counter = ({ label, value, testId }: { label: string; value: string; testId: string }) => (
  <Card padding="small">
    <Stack gap={0.5} data-testid={testId}>
      <Typography variant="body2" color="text.secondary">{label}</Typography>
      <Typography variant="h2" component="span">{value}</Typography>
    </Stack>
  </Card>
);

interface IndicatorDeploymentProps {
  indicator: IndicatorDeployment_indicator$key;
}

/** Where the indicator is live, with which proof: deployed-on relationships written back by the stream connectors. */
const IndicatorDeployment = ({ indicator }: IndicatorDeploymentProps) => {
  const { t_i18n, n } = useFormatter();
  const data = useFragment(indicatorDeploymentFragment, indicator);
  return (
    <Stack gap={3} data-testid="indicator-deployment-tab">
      <Stack direction="row" alignItems="flex-start" justifyContent="space-between" gap={2}>
        <Grid container spacing={2} sx={{ flex: 1 }}>
          <Grid item xs={6} md={3}>
            <Counter testId="indicator-live-platforms" label={t_i18n('Live platforms')} value={n(data.deployment_platforms_count ?? 0)} />
          </Grid>
          <Grid item xs={6} md={3}>
            <Counter testId="indicator-failed-deployments" label={t_i18n('Failed deployments')} value={n(data.deployment_failed_count ?? 0)} />
          </Grid>
          <Grid item xs={6} md={3}>
            <Counter testId="indicator-validated-platforms" label={t_i18n('Validated platforms')} value={n(data.validated_platforms_count ?? 0)} />
          </Grid>
          <Grid item xs={6} md={3}>
            <Counter testId="indicator-hit-platforms" label={t_i18n('Platforms with hits')} value={n(data.hit_platforms_count ?? 0)} />
          </Grid>
        </Grid>
        <Stack direction="row" gap={1}>
          <DisseminationAssuranceLink />
          <LiveDeploymentsValidationButton side="indicator" entityId={data.id} entityName={data.name} />
        </Stack>
      </Stack>
      <DeployedOnRelationships side="indicator" entityId={data.id} />
    </Stack>
  );
};

export default IndicatorDeployment;
