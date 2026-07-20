import { graphql, useLazyLoadQuery } from 'react-relay';
import React, { useEffect, useState, useContext } from 'react';
import { useTheme } from '@mui/styles';
import XtmHubTab from '@components/settings/xtm-hub/XtmHubTab';
import XtmHubUnregisteredSection from '@components/settings/xtm-hub/XtmHubUnregisteredSection';
import XtmHubRegisteredSection from '@components/settings/xtm-hub/XtmHubRegisteredSection';
import { useFormatter } from 'src/components/i18n';
import type { Theme } from 'src/components/Theme';
import { XtmHubSettingsQuery } from './__generated__/XtmHubSettingsQuery.graphql';
import useGranted, { SETTINGS_SETMANAGEXTMHUB } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { UserContext } from 'src/utils/hooks/useAuth';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Card from '../../../../components/common/card/Card';

export const xtmHubSettingsQuery = graphql`
  query XtmHubSettingsQuery {
    settings {
      id
      xtm_hub_registration_date
      xtm_hub_registration_status
      xtm_hub_registration_user_id
      xtm_hub_registration_user_name
      xtm_hub_last_connectivity_check
      xtm_hub_backend_is_reachable
      xtm_hub_token
    }
  }
`;

export const checkHubConnectivity = graphql`
  mutation XtmHubSettingsCheckConnectivityMutation {
    checkXTMHubConnectivity {
      status
    }
  }
`;

const XtmHubSettingsComponent = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { settings: xtmHubSettings } = useLazyLoadQuery<XtmHubSettingsQuery>(
    xtmHubSettingsQuery,
    {},
    { fetchPolicy: 'network-only' },
  );
  const isGrantedToXtmHub = useGranted([SETTINGS_SETMANAGEXTMHUB]);
  const { isXTMHubAccessible } = useContext(UserContext);

  const isConnected = xtmHubSettings.xtm_hub_registration_status === 'registered'
    || xtmHubSettings.xtm_hub_registration_status === 'lost_connectivity';

  const canManageXtmHub = isGrantedToXtmHub
    && isXTMHubAccessible
    && xtmHubSettings.xtm_hub_backend_is_reachable;

  return (
    <Card title={t_i18n('XTM Hub')} sx={{ border: `1px solid ${theme.palette.border.primary}` }}>
      {isConnected && canManageXtmHub && (
        <XtmHubTab
          registrationStatus={xtmHubSettings.xtm_hub_registration_status || undefined}
          renderTrigger={(handleOpen) => (
            <XtmHubRegisteredSection
              registrationStatus={xtmHubSettings.xtm_hub_registration_status ?? ''}
              registrationDate={xtmHubSettings.xtm_hub_registration_date}
              registrationUserName={xtmHubSettings.xtm_hub_registration_user_name}
              onDisconnect={handleOpen}
            />
          )}
        />
      )}

      {isConnected && !canManageXtmHub && (
        <XtmHubRegisteredSection
          registrationStatus={xtmHubSettings.xtm_hub_registration_status ?? ''}
          registrationDate={xtmHubSettings.xtm_hub_registration_date}
          registrationUserName={xtmHubSettings.xtm_hub_registration_user_name}
        />
      )}

      {!isConnected && canManageXtmHub && (
        <XtmHubTab
          registrationStatus={xtmHubSettings.xtm_hub_registration_status || undefined}
          renderTrigger={(handleOpen) => (
            <XtmHubUnregisteredSection onConnect={handleOpen} />
          )}
        />
      )}

      {!isConnected && !canManageXtmHub && (
        <XtmHubUnregisteredSection />
      )}
    </Card>
  );
};

const XtmHubSettings: React.FC = () => {
  const [commitCheckConnectivity] = useApiMutation(checkHubConnectivity);
  const [isCheckDone, setIsCheckDone] = useState(false);

  useEffect(() => {
    commitCheckConnectivity({
      variables: {},
      onCompleted: () => {
        setIsCheckDone(true);
      },
    });
  }, []);

  if (!isCheckDone) {
    return <Loader variant={LoaderVariant.inElement} />;
  }

  return <XtmHubSettingsComponent />;
};

export default XtmHubSettings;
