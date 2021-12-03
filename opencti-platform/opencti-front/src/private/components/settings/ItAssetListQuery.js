import graphql from 'babel-plugin-relay/macro';

// eslint-disable-next-line import/prefer-default-export
export const itAssetListQuery = graphql`
    query ItAssetListQuery {
      itAssetList {
        edges {
          node {
            asset_type
            vendor_name
            operational_status
          }
        }
      }
    }
`;
