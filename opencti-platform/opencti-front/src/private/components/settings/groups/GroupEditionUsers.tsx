import React, { FunctionComponent, ReactNode } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Checkbox from '@mui/material/Checkbox';
import { UsersLinesSearchQuery } from '@components/settings/users/__generated__/UsersLinesSearchQuery.graphql';
import { GroupEditionContainer_group$data } from '@components/settings/groups/__generated__/GroupEditionContainer_group.graphql';
import { GroupUsersLinesQuery$variables } from '@components/settings/users/__generated__/GroupUsersLinesQuery.graphql';
import { usersLinesSearchQuery } from '../users/UsersLines';
import { deleteNodeFromId, insertNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DataTableWithoutFragment from '../../../../components/dataGrid/DataTableWithoutFragment';
import { DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';

const userMutationRelationAdd = graphql`
  mutation GroupEditionUsersRelationAddMutation(
    $id: ID!
    $input: InternalRelationshipAddInput!
  ) {
    groupEdit(id: $id) {
      relationAdd(input: $input) {
        to {
          ...GroupEditionContainer_group
        }
        from {
          ...UserLine_node
        }
      }
    }
  }
`;

const userMutationRelationDelete = graphql`
  mutation GroupEditionUsersRelationDeleteMutation(
    $id: ID!
    $fromId: StixRef!
    $relationship_type: String!
  ) {
    groupEdit(id: $id) {
      relationDelete(fromId: $fromId, relationship_type: $relationship_type) {
        id
        ...GroupEditionContainer_group
      }
    }
  }
`;

interface GroupEditionUsersProps {
  group: GroupEditionContainer_group$data,
  queryRef: PreloadedQuery<UsersLinesSearchQuery>,
  paginationOptionsForUpdater: GroupUsersLinesQuery$variables,
  children: ReactNode,
}

const GroupEditionUsers: FunctionComponent<GroupEditionUsersProps> = ({ group, queryRef, paginationOptionsForUpdater, children }) => {
  const groupId = group.id;
  const groupUsers = group.members?.edges?.map((n) => ({ id: n.node.id })) ?? [];
  const usersData = usePreloadedQuery<UsersLinesSearchQuery>(usersLinesSearchQuery, queryRef);
  const users = usersData.users?.edges.map((n) => n.node) ?? [];

  const [commitAddUser] = useApiMutation(userMutationRelationAdd);
  const [commitRemoveUser] = useApiMutation(userMutationRelationDelete);
  const handleToggle = (userId: string, groupUser: { id: string } | undefined, event: React.ChangeEvent<HTMLInputElement>) => {
    const input = {
      fromId: userId,
      relationship_type: 'member-of',
    };
    if (event.target.checked) {
      commitAddUser({
        variables: {
          id: groupId,
          input,
        },
        updater: (store) => {
          insertNode(
            store,
            'Pagination_group_members',
            paginationOptionsForUpdater,
            'groupEdit',
            groupId,
            'relationAdd',
            { input },
            'from',
          );
        },
      });
    } else if (groupUser !== undefined) {
      commitRemoveUser({
        variables: {
          id: groupId,
          fromId: groupUser.id,
          relationship_type: 'member-of',
        },
        updater: (store) => {
          deleteNodeFromId(store, groupId, 'Pagination_group_members', paginationOptionsForUpdater, groupUser.id);
        },
      });
    }
  };

  return (
    <DataTableWithoutFragment
      dataColumns={{
        name: { percentWidth: 50, isSortable: false },
        user_email: {},
      }}
      storageKey={`group-${group.id}-users`}
      data={users}
      globalCount={users.length}
      filtersComponent={children}
      variant={DataTableVariant.inline}
      disableNavigation
      actions={(user) => {
        const groupUser = groupUsers.find((g) => g.id === user.id);
        return (
          <Checkbox
            onClick={(event) => handleToggle(
              user.id,
              groupUser,
              event as unknown as React.ChangeEvent<HTMLInputElement>,
            )}
            checked={groupUser !== undefined}
          />
        );
      }}
    />
  );
};

export default GroupEditionUsers;
