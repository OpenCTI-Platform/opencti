import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import EEChip from '@components/common/entreprise_edition/EEChip';
import RoleEditionOverview from './RoleEditionOverview';
import RoleEditionCapabilities, { roleEditionCapabilitiesLinesSearch } from './RoleEditionCapabilities';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { RoleEditionCapabilitiesLinesSearchQuery } from './__generated__/RoleEditionCapabilitiesLinesSearchQuery.graphql';
import { RoleEdition_role$key } from './__generated__/RoleEdition_role.graphql';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import { RootRoleEditionQuery$data } from './__generated__/RootRoleEditionQuery.graphql';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';

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
  roleRef: RootRoleEditionQuery$data['role'];
  handleClose?: () => void;
  open?: boolean;
  disabled?: boolean;
}

const RoleEditionDrawer: FunctionComponent<RoleEditionDrawerProps> = ({
  handleClose = () => { },
  roleRef,
  open,
  disabled = false,
}) => {
  const { t_i18n } = useFormatter();
  const [currentTab, setCurrentTab] = useState('overview');
  const queryRef = useQueryLoading<RoleEditionCapabilitiesLinesSearchQuery>(roleEditionCapabilitiesLinesSearch);
  const role = useFragment<RoleEdition_role$key>(RoleEditionFragment, roleRef);
  const isEnterpriseEdition = useEnterpriseEdition();

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
      {role ? (
        <>
          <Tabs value={currentTab} onValueChange={setCurrentTab}>
            <TabsList>
              <TabsTrigger value="overview">{t_i18n('Overview')}</TabsTrigger>
              <TabsTrigger value="capabilities">{t_i18n('Capabilities')}</TabsTrigger>
              <TabsTrigger value="capabilities-draft" disabled={!isEnterpriseEdition}>
                {t_i18n('Capabilities in Draft')}
                <EEChip clickable={false} />
              </TabsTrigger>
            </TabsList>
            <TabsContent value="overview">
              <RoleEditionOverview role={role} context={role.editContext} />
            </TabsContent>
            <TabsContent value="capabilities">
              {queryRef && <RoleEditionCapabilities role={role} queryRef={queryRef} />}
            </TabsContent>
            <TabsContent value="capabilities-draft">
              {queryRef && <RoleEditionCapabilities role={role} queryRef={queryRef} isCapabilitiesInDraft />}
            </TabsContent>
          </Tabs>
        </>
      )
        : (<Loader />)}
    </Drawer>
  );
};

interface RoleEditionProps {
  roleEditionData?: RootRoleEditionQuery$data;
  handleClose?: () => void;
  open?: boolean;
  disabled?: boolean;
}

const RoleEdition: FunctionComponent<RoleEditionProps> = ({
  roleEditionData,
  handleClose = () => { },
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
