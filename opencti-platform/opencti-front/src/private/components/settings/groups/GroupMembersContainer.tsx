import List from '@mui/material/List';
import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import * as R from 'ramda';
import UserLineTitles from '../users/UserLineTitles';
import { UserLine } from '../users/UserLine';
import { GroupMembersContainerQuery } from './__generated__/GroupMembersContainerQuery.graphql';
import { DataColumns } from '../../../../components/list_lines';

export const groupMembersContainerQuery = graphql`
    query GroupMembersContainerQuery($id: String!, $search: String) {
        group(id: $id) {
            id
            name
            members(search: $search) {
                edges {
                    node {
                        id
                        user_email
                        name
                        firstname
                        lastname
                        external
                    }
                }
            }
        }
    }
`;

interface GroupMembersContainerProps {
  userColumns: DataColumns,
  queryRef: PreloadedQuery<GroupMembersContainerQuery>,
}

const GroupMembersContainer: FunctionComponent<GroupMembersContainerProps> = ({ userColumns, queryRef }) => {
  const groupWithMembersData = usePreloadedQuery<GroupMembersContainerQuery>(groupMembersContainerQuery, queryRef);
  const membersData = groupWithMembersData.group?.members;
  const usersSort = R.sortWith([R.ascend(R.pathOr('name', ['node', 'name']))]);
  const members = usersSort(membersData?.edges ?? []);
  return (
    <div>
    <UserLineTitles dataColumns={userColumns} />
      <List>
        {members.map((member) => (
          <UserLine
            key={member?.node?.id}
            dataColumns={userColumns}
            node={member?.node}
          />
        ))}
      </List>
    </div>
  );
};

export default GroupMembersContainer;
