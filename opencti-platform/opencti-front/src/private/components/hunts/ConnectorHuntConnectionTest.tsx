import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { useTheme } from '@mui/styles';
import Card from '../../../components/common/card/Card';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { HuntConnectorRequiredPermissions, HuntConnectorTestConnection } from './HuntConnectorSetup';
import type { ConnectorHuntConnectionTest_hunt$key } from './__generated__/ConnectorHuntConnectionTest_hunt.graphql';

const connectorHuntConnectionTestFragment = graphql`
  fragment ConnectorHuntConnectionTest_hunt on HuntConnector {
    active
    documentation_url
    required_permissions {
      name
      purpose
    }
    connection_check {
      id
      status
      requested_at
      checked_at
      checks {
        name
        ok
        message
      }
    }
  }
`;

interface ConnectorHuntConnectionTestProps {
  connectorId: string;
  data: ConnectorHuntConnectionTest_hunt$key;
}

/**
 * Connection test of an INTERNAL_HUNT connector on its connector page: the permissions its account needs on its
 * platform, its setup documentation and the test of both. The hunts it runs stay in Defense > Hunts.
 */
const ConnectorHuntConnectionTest = ({ connectorId, data }: ConnectorHuntConnectionTestProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const hunt = useFragment(connectorHuntConnectionTestFragment, data);
  return (
    <Card title={t_i18n('Connection test')}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }}>
        <HuntConnectorTestConnection connectorId={connectorId} active={hunt.active} check={hunt.connection_check} />
        <HuntConnectorRequiredPermissions
          permissions={hunt.required_permissions}
          documentationUrl={hunt.documentation_url}
          defaultOpen={hunt.connection_check?.status !== 'passed'}
        />
      </div>
    </Card>
  );
};

export default ConnectorHuntConnectionTest;
