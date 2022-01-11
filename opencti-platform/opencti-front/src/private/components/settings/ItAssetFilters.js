import graphql from 'babel-plugin-relay/macro';

// eslint-disable-next-line import/prefer-default-export
export const itAssetFiltersDeviceFieldsQuery = graphql`
  query ItAssetFiltersDeviceFieldsQuery(
    $search: String
    # $first: Int
  ) {
    computingDeviceAssetList(search: $search) {
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
  query ItAssetFiltersNetworkFieldsQuery(
    $search: String
    # $first: Int
  ) {
    networkAssetList(search: $search) {
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
  query ItAssetFiltersSoftwareFieldsQuery(
    $search: String
    # $first: Int
  ) {
    softwareAssetList(search: $search) {
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
