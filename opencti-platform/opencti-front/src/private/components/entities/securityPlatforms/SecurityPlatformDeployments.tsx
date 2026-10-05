import { Stack } from '@mui/material';
import DeployedOnRelationships from '../../data/dissemination_assurance/DeployedOnRelationships';
import DisseminationAssuranceLink from '../../data/dissemination_assurance/DisseminationAssuranceLink';
import DisseminationAssuranceMetrics from '../../data/dissemination_assurance/DisseminationAssuranceMetrics';
import LiveDeploymentsValidationButton from '../../data/dissemination_assurance/LiveDeploymentsValidationButton';

interface SecurityPlatformDeploymentsProps {
  securityPlatformId: string;
}

/** Indicators the stream connectors deployed on this platform, their lifecycle, hits and validation proof. */
const SecurityPlatformDeployments = ({ securityPlatformId }: SecurityPlatformDeploymentsProps) => (
  <Stack gap={3} data-testid="security-platform-deployments-tab">
    <Stack direction="row" justifyContent="flex-end" gap={1}>
      <DisseminationAssuranceLink />
      <LiveDeploymentsValidationButton side="platform" entityId={securityPlatformId} />
    </Stack>
    <DisseminationAssuranceMetrics
      platformId={securityPlatformId}
      renderDeployments={(kpiFilters) => <DeployedOnRelationships side="platform" entityId={securityPlatformId} kpiFilters={kpiFilters} />}
    />
  </Stack>
);

export default SecurityPlatformDeployments;
