/*
Copyright (c) 2021-2023 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql, useMutation } from 'react-relay';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import Checkbox from '@mui/material/Checkbox';
import { AccountBalanceOutlined } from '@mui/icons-material';
import EnterpriseEdition from '../../common/entreprise_edition/EnterpriseEdition';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { useFormatter } from '../../../../components/i18n';

const userEditionOrganizationsAdminAddMutation = graphql`
  mutation UserEditionOrganizationsAdminAddMutation(
    $id: ID!
    $memberId: String!
    $userEmail: Any!
  ) {
    organizationAdminAdd(id: $id, memberId: $memberId) {
      id
      members (filters: { mode: and, filters: [{ key: "user_email", values: [$userEmail] }], filterGroups: [] } ) {
        edges {
          node {
            id
            ...UserEditionOrganizationsAdmin_user
          }
        }
      }
    }
  }
`;
const userEditionOrganizationsAdminRemoveMutation = graphql`
  mutation UserEditionOrganizationsAdminRemoveMutation(
    $id: ID!
    $memberId: String!
    $userEmail: Any!
  ) {
    organizationAdminRemove(id: $id, memberId: $memberId) {
      id
      members (filters: { mode: and, filters: [{ key: "user_email", values: [$userEmail] }], filterGroups: [] } ) {
        edges {
          node {
            id
            ...UserEditionOrganizationsAdmin_user
          }
        }
      }
    }
  }
`;

const UserEditionOrganizationsAdminComponent = ({ user }) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t } = useFormatter();

  const [promoteMemberMutation] = useMutation(userEditionOrganizationsAdminAddMutation);
  const [demoteMemberMutation] = useMutation(userEditionOrganizationsAdminRemoveMutation);

  const handleToggle = (organizationId, event) => {
    if (event.target.checked) {
      promoteMemberMutation({
        variables: {
          id: organizationId,
          memberId: user.id,
          userEmail: user.user_email,
        },
      });
    } else {
      demoteMemberMutation({
        variables: {
          id: organizationId,
          memberId: user.id,
          userEmail: user.user_email,
        },
      });
    }
  };
  if (!isEnterpriseEdition) {
    return <div style={{ marginTop: 20 }}><EnterpriseEdition feature={t('Organization sharing')} /></div>;
  }
  return (
    <List>
      {(user?.objectOrganization?.edges ?? []).map(({ node: organization }) => {
        const isAdmin = (organization.authorized_authorities ?? []).includes(user.id);
        return (
          <ListItem key={organization.id} divider={true}>
            <ListItemIcon color="primary">
              <AccountBalanceOutlined />
            </ListItemIcon>
            <ListItemText primary={organization.name} secondary={organization.description ?? ''}/>
            <ListItemSecondaryAction>
              <Checkbox onChange={(event) => handleToggle(organization.id, event)} checked={isAdmin}/>
            </ListItemSecondaryAction>
          </ListItem>
        );
      })}
    </List>
  );
};

UserEditionOrganizationsAdminComponent.propTypes = {
  user: PropTypes.object,
};

const UserEditionOrganizationsAdmin = createFragmentContainer(UserEditionOrganizationsAdminComponent, {
  user: graphql`
    fragment UserEditionOrganizationsAdmin_user on User
    @argumentDefinitions(
      organizationsOrderBy: { type: "OrganizationsOrdering", defaultValue: name }
      organizationsOrderMode: { type: "OrderingMode", defaultValue: asc }
    ) {
      id
      user_email
      objectOrganization(orderBy: $organizationsOrderBy, orderMode: $organizationsOrderMode) {
        edges {
          node {
            id
            name
            description
            authorized_authorities
          }
        }
      }
    }
  `,
});

export default UserEditionOrganizationsAdmin;
