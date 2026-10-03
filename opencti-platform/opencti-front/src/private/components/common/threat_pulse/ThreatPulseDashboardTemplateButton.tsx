import React, { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useNavigate } from 'react-router';
import { ScaleBalance } from 'mdi-material-ui';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import { serializeDashboardManifestForBackend } from '../../../../components/dashboard/dashboard-utils';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { resolveLink } from '../../../../utils/Entity';
import { ThreatPulseDashboardTemplateButtonQuery } from './__generated__/ThreatPulseDashboardTemplateButtonQuery.graphql';
import { ThreatPulseDashboardTemplateButtonMutation } from './__generated__/ThreatPulseDashboardTemplateButtonMutation.graphql';
import { buildSectorBenchmarkDashboard } from './threatPulseDashboardTemplate';

const threatPulseDashboardTemplateButtonQuery = graphql`
  query ThreatPulseDashboardTemplateButtonQuery {
    pulseStatus {
      id
      access
    }
  }
`;

const threatPulseDashboardTemplateButtonMutation = graphql`
  mutation ThreatPulseDashboardTemplateButtonMutation($input: WorkspaceDuplicateInput!) {
    workspaceDuplicate(input: $input) {
      id
    }
  }
`;

const ThreatPulseDashboardTemplateButtonComponent = () => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const { pulseStatus } = useLazyLoadQuery<ThreatPulseDashboardTemplateButtonQuery>(threatPulseDashboardTemplateButtonQuery, {}, { fetchPolicy: 'store-and-network' });
  const [commit, creating] = useApiMutation<ThreatPulseDashboardTemplateButtonMutation>(threatPulseDashboardTemplateButtonMutation);
  if (pulseStatus.access !== 'preview' && pulseStatus.access !== 'full') {
    return null;
  }
  const create = () => {
    commit({
      variables: {
        input: {
          type: 'dashboard',
          name: t_i18n('Sector benchmark'),
          description: t_i18n('Threat Pulse: what rises in your sector and how this platform compares with the sector median.'),
          manifest: serializeDashboardManifestForBackend(buildSectorBenchmarkDashboard(t_i18n)),
        },
      },
      onCompleted: (response) => {
        if (response.workspaceDuplicate?.id) {
          navigate(`${resolveLink('Dashboard')}/${response.workspaceDuplicate.id}`);
        }
      },
    });
  };
  return (
    <Button
      variant="secondary"
      onClick={create}
      disabled={creating}
      startIcon={<ScaleBalance fontSize="small" />}
      title={t_i18n('Create the Sector benchmark dashboard from the Threat Pulse template')}
      data-testid="threat-pulse-dashboard-template"
    >
      {t_i18n('Sector benchmark template')}
    </Button>
  );
};

// Creates the "Sector benchmark" dashboard, offered in preview too: its tiles then name what contributing unlocks.
const ThreatPulseDashboardTemplateButton = () => (
  <Suspense fallback={null}>
    <ThreatPulseDashboardTemplateButtonComponent />
  </Suspense>
);

export default ThreatPulseDashboardTemplateButton;
