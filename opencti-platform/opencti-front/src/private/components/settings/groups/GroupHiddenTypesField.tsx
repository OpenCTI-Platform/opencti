import { graphql, useFragment, useMutation } from 'react-relay';
import HiddenTypesField from '../hidden_types/HiddenTypesField';
import { GroupHiddenTypesField_group$key } from './__generated__/GroupHiddenTypesField_group.graphql';

const groupHiddenTypesFieldPatch = graphql`
  mutation GroupHiddenTypesFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    groupEdit(id: $id) {
      fieldPatch(input: $input) {
        ...GroupHiddenTypesField_group
      }
    }
  }
`;

const groupHiddenTypesFieldFragment = graphql`
  fragment GroupHiddenTypesField_group on Group {
    id
    default_hidden_types
  }
`;

const GroupHiddenTypesField = ({
  groupData,
}: {
  groupData: GroupHiddenTypesField_group$key
}) => {
  const group = useFragment<GroupHiddenTypesField_group$key>(groupHiddenTypesFieldFragment, groupData);
  const [commit] = useMutation(groupHiddenTypesFieldPatch);

  const handleChange = (newValues: string[]) => {
    commit({
      variables: {
        id: group?.id, input: { key: 'default_hidden_types', value: newValues },
      },
    });
  };

  return (
    <HiddenTypesField
      initialValues={(group.default_hidden_types ?? []) as string[]}
      handleChange={handleChange}
    />
  );
};

export default GroupHiddenTypesField;
