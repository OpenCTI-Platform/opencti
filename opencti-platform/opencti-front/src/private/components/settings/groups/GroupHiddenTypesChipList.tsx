import React from 'react';
import { graphql, useFragment } from 'react-relay';
import HiddenTypesChipList from '../hidden_types/HiddenTypesChipList';
import { Group_group$data } from './__generated__/Group_group.graphql';
import { GroupHiddenTypesChipList_group$key } from './__generated__/GroupHiddenTypesChipList_group.graphql';

const groupHiddenTypesFragment = graphql`
  fragment GroupHiddenTypesChipList_group on Group {
    default_hidden_types
  }
`;

const GroupHiddenTypesChipList = ({
  groupData,
}: {
  groupData: Group_group$data
}) => {
  const group = useFragment(groupHiddenTypesFragment, groupData as unknown as GroupHiddenTypesChipList_group$key);

  const hiddenTypesGroup = group?.default_hidden_types ?? [];

  return (
      <HiddenTypesChipList hiddenTypes={hiddenTypesGroup}/>
  );
};

export default GroupHiddenTypesChipList;
