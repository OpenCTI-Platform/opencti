import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import RoleEditionOverview from './RoleEditionOverview';
import RoleEditionCapabilities, { roleEditionCapabilitiesLinesSearch } from './RoleEditionCapabilities';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { RoleEditionCapabilitiesLinesSearchQuery } from './__generated__/RoleEditionCapabilitiesLinesSearchQuery.graphql';
import { RoleEdition_role$key } from './__generated__/RoleEdition_role.graphql';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import { RootRoleEditionQuery$data } from './__generated__/RootRoleEditionQuery.graphql';

const RoleEditionFragment = graphql`
  fragment RoleEdition_role on Role {
    id
    standard_id
    ...RoleEditionOverview_role
    ...RoleEditionCapabilities_role
    editContext {
      name
      focusOn
    }
  }
`;

interface RoleEditionDrawerProps {
  roleRef: RootRoleEditionQuery$data['role']
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
  const queryRef = useQueryLoading<RoleEditionCapabilitiesLinesSearchQuery>(roleEditionCapabilitiesLinesSearch);
  const role = useFragment<RoleEdition_role$key>(RoleEditionFragment, roleRef);

  const UpdateRoleControlledDial = (props: DrawerControlledDialProps) => (
    <EditEntityControlledDial
      style={{ float: 'right' }}
      disabled={disabled}
      {...props}
    />
  );

  return (
    <Drawer
      title={t_i18n('Update a role')}
      open={open}
      onClose={handleClose}
      context={role?.editContext}
      disabled={disabled}
      controlledDial={UpdateRoleControlledDial}
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
          <RoleEditionCapabilities role={role} queryRef={queryRef} />
        )}
      </>)
        : (<Loader />)}
    </Drawer>
  );
};

interface RoleEditionProps {
  roleEditionData?: RootRoleEditionQuery$data
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
