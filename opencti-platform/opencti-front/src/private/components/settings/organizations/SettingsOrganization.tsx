import { graphql } from 'react-relay';

const settingsOrganizationFragment = graphql`
  fragment SettingsOrganization_organization on Organization {
    id
    standard_id
#     ...SettingsOrganizationDetails_organization
  }
`;
// TODO Add Details fragment once created
const SettingsOrganization = () => {
  console.log(settingsOrganizationFragment);

};
export default SettingsOrganization;
