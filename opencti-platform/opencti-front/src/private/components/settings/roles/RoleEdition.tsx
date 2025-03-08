import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import RoleEditionOverview from './RoleEditionOverview';
import RoleEditionCapabilities, { roleEditionCapabilitiesLinesSearch } from './RoleEditionCapabilities';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { RoleEditionCapabilitiesLinesSearchQuery } from './__generated__/RoleEditionCapabilitiesLinesSearchQuery.graphql';
import { RoleEdition_role$key } from './__generated__/RoleEdition_role.graphql';
import { RolePopoverEditionQuery$data } from './__generated__/RolePopoverEditionQuery.graphql';
import useHelper from '../../../../utils/hooks/useHelper';
import UpdateRoleControlledDial from '../../../../components/UpdateEntityControlledDial';

const RoleEditionFragment = graphql`
  fragment RoleEdition_role on Role {
    id
    ...RoleEditionOverview_role
    ...RoleEditionCapabilities_role
    editContext {
      name
      focusOn
    }
  }
`;

interface RoleEditionDrawerProps {
  roleRef: RolePopoverEditionQuery$data['role']
  handleClose?: () => void
  open?: boolean
  disabled?: boolean
}

const RoleEditionDrawer: FunctionComponent<RoleEditionDrawerProps> = ({
  handleClose = () => {},
  roleRef,
  open,
  disabled = false,
}) => {
  const { t_i18n } = useFormatter();
  const [currentTab, setCurrentTab] = useState(0);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const queryRef = useQueryLoading<RoleEditionCapabilitiesLinesSearchQuery>(roleEditionCapabilitiesLinesSearch);
  const role = useFragment<RoleEdition_role$key>(RoleEditionFragment, roleRef);

  return (
    <Drawer
      title={t_i18n('Update a role')}
      variant={open == null && !isFABReplaced
        ? DrawerVariant.updateWithPanel
        : undefined}
      open={open}
      onClose={handleClose}
      context={role?.editContext}
      disabled={disabled}
      controlledDial={isFABReplaced
        ? UpdateRoleControlledDial
        : undefined
      }
    >
      {role ? (<>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={currentTab} onChange={(_, value) => setCurrentTab(value)}>
            <Tab label={t_i18n('Overview')} />
            <Tab label={t_i18n('Capabilities')} />
          </Tabs>
        </Box>
        {currentTab === 0 && <RoleEditionOverview role={role} context={role.editContext} />}
        {currentTab === 1 && queryRef && (
          <React.Suspense
            fallback={<Loader variant={LoaderVariant.inline} />}
          >
            <RoleEditionCapabilities role={role} queryRef={queryRef} />
          </React.Suspense>
        )}
      </>)
        : (<Loader />)}
    </Drawer>
  );
};

interface RoleEditionProps {
  roleEditionData?: RolePopoverEditionQuery$data
  handleClose?: () => void
  open?: boolean
  disabled?: boolean
}

const RoleEdition: FunctionComponent<RoleEditionProps> = ({
  roleEditionData,
  handleClose = () => {},
  open,
  disabled = false,
}) => {
  if (!roleEditionData) return <Loader />;
  return (
    <RoleEditionDrawer
      roleRef={roleEditionData.role}
      handleClose={handleClose}
      open={open}
      disabled={disabled}
    />
  );
};

export default RoleEdition;
