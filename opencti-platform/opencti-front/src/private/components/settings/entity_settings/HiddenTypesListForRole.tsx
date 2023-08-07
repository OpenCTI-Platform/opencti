import { FunctionComponent } from 'react';
import { graphql, useMutation } from 'react-relay';
import { RoleEditionOverview_role$data } from '../roles/__generated__/RoleEditionOverview_role.graphql';
import HiddenTypesList from './HiddenTypesList';

const hiddenTypesListForRolePatchM = graphql`
  mutation HiddenTypesListForRolePatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    roleEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        name
        default_hidden_types
      }
    }
  }
`;

interface HiddenTypesListForRoleProps {
  role: RoleEditionOverview_role$data,
}

const HiddenTypesListForRole: FunctionComponent<HiddenTypesListForRoleProps> = ({
  role,
}) => {
  const [commit] = useMutation(hiddenTypesListForRolePatchM);

  const handleChange = (newValues: string[]) => {
    commit({
      variables: {
        id: role?.id,
        input: { key: 'default_hidden_types', value: newValues },
      },
    });
  };

  return (
    <HiddenTypesList
      initialValues={(role.default_hidden_types ?? []) as string[]}
      handleChange={handleChange}
    />
  );
};

export default HiddenTypesListForRole;
