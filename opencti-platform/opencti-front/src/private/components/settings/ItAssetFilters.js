import graphql from 'babel-plugin-relay/macro';

// eslint-disable-next-line import/prefer-default-export
export const itAssetFiltersDeviceFieldsQuery = graphql`
  query ItAssetFiltersDeviceFieldsQuery {
    computingDeviceAssetList {
      edges {
        node {
          id
          name
          labels
        }
      }
    }
  }
`;

// eslint-disable-next-line import/prefer-default-export
export const itAssetFiltersNetworkFieldsQuery = graphql`
  query ItAssetFiltersNetworkFieldsQuery {
    networkAssetList {
      edges {
        node {
          id
          name
          labels
        }
      }
    }
  }
`;

// eslint-disable-next-line import/prefer-default-export
export const itAssetFiltersSoftwareFieldsQuery = graphql`
  query ItAssetFiltersSoftwareFieldsQuery {
    softwareAssetList {
      edges {
        node {
          id
          name
          labels
          vendor_name
        }
      }
    }
  }
`;

// eslint-disable-next-line import/prefer-default-export
export const itAssetFiltersAssetTypeFieldQuery = graphql`
  query ItAssetFiltersAssetTypeFieldQuery(
    $type: String!
  ) {
    __type(name: $type) {
      name
      description
      enumValues {
        name
        description
      }
    }
  }
`;
