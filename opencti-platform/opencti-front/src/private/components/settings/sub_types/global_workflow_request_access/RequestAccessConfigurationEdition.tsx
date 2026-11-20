import { graphql } from 'react-relay';

export const requestAccessConfigurationFragment = graphql`
  fragment RequestAccessConfigurationEdition_requestAccess on RequestAccessConfiguration {
    id
    approved_status {
      id
      template {
        id
        color
        name
      }
    }
    declined_status {
      id
      template {
        id
        color
        name
      }
    }
    approval_admin {
      id
      name
    }
  }
`;
