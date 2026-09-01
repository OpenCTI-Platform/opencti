import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import EEChip from '@components/common/entreprise_edition/EEChip';
import UserEditionConfidence from './edition/UserEditionConfidence';
import UserEditionOrganizationsAdmin from './edition/UserEditionOrganizationsAdmin';
import UserEditionOverview from './edition/UserEditionOverview';
import UserEditionPassword from './edition/UserEditionPassword';
import UserEditionGroups from './edition/UserEditionGroups';
import { useFormatter } from '../../../../components/i18n';
import { UserEdition_user$key } from './__generated__/UserEdition_user.graphql';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import { RootUserEditionQuery$data } from './__generated__/RootUserEditionQuery.graphql';
import Loader from '../../../../components/Loader';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';

const UserEditionFragment = graphql`
  fragment UserEdition_user on User
  @argumentDefinitions(
    groupsOrderBy: { type: "GroupsOrdering", defaultValue: name }
    groupsOrderMode: { type: "OrderingMode", defaultValue: asc }
    organizationsCount: { type: "Int", defaultValue: 500 }
    organizationsOrderBy: { type: "OrganizationsOrdering", defaultValue: name }
    organizationsOrderMode: { type: "OrderingMode", defaultValue: asc }
  ) {
    id
    external
    user_service_account
    user_confidence_level {
      max_confidence
      overrides {
        max_confidence
        entity_type
      }
    }
    effective_confidence_level {
      max_confidence
      overrides {
        max_confidence
        entity_type
        source {
          type
          object {
            ... on User { entity_type id name }
            ... on Group { entity_type id name }
          }
        }
      }
      source {
        type
        object {
          ... on User { entity_type id name }
          ... on Group { entity_type id name }
        }
      }
    }
    objectAssignedOrganization(first: $organizationsCount, orderBy: $organizationsOrderBy, orderMode: $organizationsOrderMode) {
      edges {
        node {
          id
          name
        }
      }
    }
    groups(orderBy: $groupsOrderBy, orderMode: $groupsOrderMode) {
      edges {
        node {
          id
          name
        }
      }
    }
    ...UserEditionOverview_user
      @arguments(
        groupsOrderBy: $groupsOrderBy
        groupsOrderMode: $groupsOrderMode
        organizationsOrderBy: $organizationsOrderBy
        organizationsOrderMode: $organizationsOrderMode
      )
    ...UserEditionPassword_user
    ...UserEditionGroups_user
      @arguments(
        groupsOrderBy: $groupsOrderBy
        groupsOrderMode: $groupsOrderMode
        organizationsOrderBy: $organizationsOrderBy
        organizationsOrderMode: $organizationsOrderMode
      )
    ...UserEditionOrganizationsAdmin_user
      @arguments(
        organizationsOrderBy: $organizationsOrderBy
        organizationsOrderMode: $organizationsOrderMode
      )
    editContext {
      name
      focusOn
    }
  }
`;

interface UserEditionDrawerProps {
  handleClose?: () => void;
  userRef: RootUserEditionQuery$data['user'];
  open?: boolean;
}

const UpdateUserControlledDial = (props: DrawerControlledDialProps) => (
  <EditEntityControlledDial
    style={{ float: 'right' }}
    {...props}
  />
);

const UserEditionDrawer: FunctionComponent<UserEditionDrawerProps> = ({
  handleClose = () => {},
  userRef,
  open,
}) => {
  const { t_i18n } = useFormatter();
  const hasSetAccess = useGranted([SETTINGS_SETACCESSES]);
  const user = useFragment<UserEdition_user$key>(UserEditionFragment, userRef);
  const isServiceAccount = user?.user_service_account;
  const [currentTab, setCurrentTab] = useState('overview');
  const handleChangeTab = (value: string) => {
    setCurrentTab(value);
  };
  return (
    <Drawer
      title={isServiceAccount ? t_i18n('Update Service account') : t_i18n('Update User')}
      open={open}
      onClose={handleClose}
      context={user?.editContext}
      controlledDial={UpdateUserControlledDial}
    >
      {user ? (
        <>
          <Tabs value={currentTab} onValueChange={handleChangeTab}>
            <TabsList>
              <TabsTrigger value="overview">{t_i18n('Overview')}</TabsTrigger>
              <TabsTrigger value="password" disabled={!!user.external || isServiceAccount === true}>{t_i18n('Password')}</TabsTrigger>
              <TabsTrigger value="groups">{t_i18n('Groups')}</TabsTrigger>
              {hasSetAccess && (
                <TabsTrigger
                  value="organizations-admin"
                  disabled={user.objectAssignedOrganization?.edges.length === 0}
                >
                  {t_i18n('Organizations admin')}<EEChip clickable={false} />
                </TabsTrigger>
              )}
              {hasSetAccess && <TabsTrigger value="confidences">{t_i18n('Confidences')}</TabsTrigger>}
            </TabsList>
            <TabsContent value="overview">
              <UserEditionOverview user={user} context={user.editContext} />
            </TabsContent>
            <TabsContent value="password">
              <UserEditionPassword user={user} />
            </TabsContent>
            <TabsContent value="groups"><UserEditionGroups user={user} /></TabsContent>
            <TabsContent value="organizations-admin">
              {hasSetAccess && <UserEditionOrganizationsAdmin user={user} />}
            </TabsContent>
            <TabsContent value="confidences">
              {hasSetAccess && <UserEditionConfidence user={user} context={user.editContext} />}
            </TabsContent>
          </Tabs>
        </>
      )
        : (<Loader />)}
    </Drawer>
  );
};

interface UserEditionProps {
  userEditionData?: RootUserEditionQuery$data;
  handleClose?: () => void;
  open?: boolean;
}

const UserEdition: FunctionComponent<UserEditionProps> = ({
  userEditionData,
  handleClose,
  open,
}) => {
  if (!userEditionData) return <Loader />;
  return (
    <UserEditionDrawer
      handleClose={handleClose}
      open={open}
      userRef={userEditionData.user}
    />
  );
};

export default UserEdition;
