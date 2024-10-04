import React, { FunctionComponent, useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
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
import { RoleEdition_role$data } from './__generated__/RoleEdition_role.graphql';

interface RoleEditionProps {
  role: RoleEdition_role$data
  handleClose?: () => void
  open?: boolean
  disabled?: boolean
  isSensitive?: boolean
}

const RoleEdition: FunctionComponent<RoleEditionProps> = ({
  handleClose = () => {},
  role,
  open,
  disabled = false,
  isSensitive = false,
}) => {
  const { t_i18n } = useFormatter();
  const [currentTab, setTab] = useState(0);
  const { editContext } = role;

  const queryRef = useQueryLoading<RoleEditionCapabilitiesLinesSearchQuery>(roleEditionCapabilitiesLinesSearch);

  return (
    <Drawer
      title={t_i18n('Update a role')}
      variant={open == null ? DrawerVariant.updateWithPanel : undefined}
      open={open}
      onClose={handleClose}
      context={editContext}
      disabled={disabled}
      isSensitive={isSensitive}
    >
      <>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={currentTab} onChange={(event, value) => setTab(value)}>
            <Tab label={t_i18n('Overview')} />
            <Tab label={t_i18n('Capabilities')} />
          </Tabs>
        </Box>
        {currentTab === 0 && <RoleEditionOverview role={role} context={editContext} />}
        {currentTab === 1 && queryRef && (
          <React.Suspense
            fallback={<Loader variant={LoaderVariant.inElement} />}
          >
            <RoleEditionCapabilities role={role} queryRef={queryRef} />
          </React.Suspense>
        )}
      </>
    </Drawer>
  );
};

const RoleEditionFragment = createFragmentContainer(RoleEdition, {
  role: graphql`
    fragment RoleEdition_role on Role {
      id
      ...RoleEditionOverview_role
      ...RoleEditionCapabilities_role
      editContext {
        name
        focusOn
      }
    }
  `,
});

export default RoleEditionFragment;
