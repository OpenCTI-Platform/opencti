import List from '@mui/material/List';
import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import * as R from 'ramda';
import { UserLine } from './UserLine';
import UserLineTitles from './UserLineTitles';
import { MembersListQuery } from './__generated__/MembersListQuery.graphql';

export const membersListQuery = graphql`
    query MembersListQuery($id: String!, $search: String) {
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

interface MembersListProps {
  queryRef: PreloadedQuery<MembersListQuery>;
}

const MembersList: FunctionComponent<MembersListProps> = ({ queryRef }) => {
  const groupWithMembersData = usePreloadedQuery<MembersListQuery>(membersListQuery, queryRef);
  const membersData = groupWithMembersData.group?.members;
  const usersSort = R.sortWith([R.ascend(R.pathOr('name', ['node', 'name']))]);
  const members = usersSort(membersData?.edges ?? []);
  const userColumns = {
    name: {
      label: 'Name',
      width: '20%',
      isSortable: true,
    },
    user_email: {
      label: 'Email',
      width: '30%',
      isSortable: true,
    },
    firstname: {
      label: 'Firstname',
      width: '15%',
      isSortable: true,
    },
    lastname: {
      label: 'Lastname',
      width: '15%',
      isSortable: true,
    },
    otp: {
      label: '2FA',
      width: '5%',
      isSortable: false,
    },
    created_at: {
      label: 'Creation date',
      width: '10%',
      isSortable: true,
    },
  };
  return (
    <div>
      <UserLineTitles dataColumns={userColumns} />
      <List>
        {members.map((member) => (
          <UserLine
            key={member?.node.id}
            dataColumns={userColumns}
            node={member?.node}
          />
        ))}
      </List>
    </div>
  );
};

export default MembersList;
