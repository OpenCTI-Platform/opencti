import { graphql, useFragment, useMutation } from 'react-relay';
import HiddenTypesField from '../hidden_types/HiddenTypesField';
import {
  SettingsOrganizationHiddenTypesField_organization$key,
} from './__generated__/SettingsOrganizationHiddenTypesField_organization.graphql';

const settingsOrganizationHiddenTypesFieldPatch = graphql`
  mutation SettingsOrganizationHiddenTypesFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    organizationFieldPatch(id: $id, input: $input) {
      ...SettingsOrganizationHiddenTypesField_organization
    }
  }
`;

const settingsOrganizationHiddenTypesFieldFragment = graphql`
  fragment SettingsOrganizationHiddenTypesField_organization on Organization {
    id
    default_hidden_types
  }
`;

const SettingsOrganizationHiddenTypesField = ({
  organizationData,
}: {
  organizationData: SettingsOrganizationHiddenTypesField_organization$key
}) => {
  const organization = useFragment<SettingsOrganizationHiddenTypesField_organization$key>(settingsOrganizationHiddenTypesFieldFragment, organizationData);
  const [commit] = useMutation(settingsOrganizationHiddenTypesFieldPatch);

  const handleChange = (newValues: string[]) => {
    commit({
      variables: {
        id: organization?.id, input: { key: 'default_hidden_types', value: newValues },
      },
    });
  };

  return (<HiddenTypesField
      initialValues={(organization.default_hidden_types ?? []) as string[]}
      handleChange={handleChange}
    />);
};

export default SettingsOrganizationHiddenTypesField;
