import React, { FunctionComponent, useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { usePaginationLocalStorage } from 'src/utils/hooks/useLocalStorage';
import RoleEditionOverview from './RoleEditionOverview';
import RoleEditionCapabilities, { roleEditionCapabilitiesLinesSearch } from './RoleEditionCapabilities';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { RoleEditionCapabilitiesLinesSearchQuery } from './__generated__/RoleEditionCapabilitiesLinesSearchQuery.graphql';
import { RoleEdition_role$data } from './__generated__/RoleEdition_role.graphql';
import RoleEditionOverride from './RoleEditionOverride';
import { SubTypesLinesQuery, SubTypesLinesQuery$variables } from '../sub_types/__generated__/SubTypesLinesQuery.graphql';
import { subTypesLinesQuery } from '../sub_types/SubTypesLines';

const LOCAL_STORAGE_KEY_SUB_TYPES = 'sub-types';

interface RoleEditionProps {
  role: RoleEdition_role$data
  handleClose?: () => void
  open?: boolean
}

const RoleEdition: FunctionComponent<RoleEditionProps> = ({
  handleClose = () => {},
  role,
  open,
}) => {
  const { t_i18n } = useFormatter();
  const [currentTab, setTab] = useState(0);
  const { editContext } = role;

  const queryRef = useQueryLoading<RoleEditionCapabilitiesLinesSearchQuery>(roleEditionCapabilitiesLinesSearch);
  const { paginationOptions } = usePaginationLocalStorage<SubTypesLinesQuery$variables>(
    LOCAL_STORAGE_KEY_SUB_TYPES,
    { searchTerm: '' },
  );
  const subTypesQueryRef = useQueryLoading<SubTypesLinesQuery>(
    subTypesLinesQuery,
    paginationOptions,
  );

  return (
    <Drawer
      title={t_i18n('Update a role')}
      variant={open == null ? DrawerVariant.updateWithPanel : undefined}
      open={open}
      onClose={handleClose}
      context={editContext}
    >
      <>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={currentTab} onChange={(event, value) => setTab(value)}>
            <Tab label={t_i18n('Overview')} />
            <Tab label={t_i18n('Capabilities')} />
            <Tab label={t_i18n('Entities Override')} />
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
        {currentTab === 2 && queryRef && subTypesQueryRef && (
          <React.Suspense
            fallback={<Loader variant={LoaderVariant.inElement} />}
          >
            <RoleEditionOverride
              role={role}
              queryRef={queryRef}
              subTypesQueryRef={subTypesQueryRef}
            />
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
      ...RoleEditionOverride_role
      editContext {
        name
        focusOn
      }
    }
  `,
});

export default RoleEditionFragment;
