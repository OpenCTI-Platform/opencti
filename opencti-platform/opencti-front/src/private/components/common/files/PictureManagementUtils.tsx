import { graphql } from 'react-relay';

export const pictureManagementUtilsMutation = graphql`
  mutation PictureManagementUtilsMutation(
    $id: ID!
    $input: StixDomainObjectFileEditInput
  ) {
    stixDomainObjectEdit(id: $id) {
      stixDomainObjectFileEdit(input: $input) {
        importFiles {
          edges {
            node {
              ...PictureManagementUtils_node
            }
          }
        }
      }
    }
  }
`;

export const pictureManagementUtilsFragment = graphql`
  fragment PictureManagementUtils_node on File {
    id
    name
    metaData {
      description
      order
      inCarousel
    }
  }
`;
