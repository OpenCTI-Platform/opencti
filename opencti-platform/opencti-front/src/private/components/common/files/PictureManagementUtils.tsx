import { graphql } from 'react-relay';

export const pictureManagementUtilsMutation = graphql`
  mutation PictureManagementUtilsMutation(
    $id: ID!
    $input: StixDomainObjectFileEditInput
  ) {
    stixDomainObjectEdit(id: $id) {
      stixDomainObjectFileEdit(input: $input) {
        x_opencti_files(prefixMimeType: "image/") {
          ...PictureManagementUtils_node
        }
      }
    }
  }
`;

export const pictureManagementUtilsFragment = graphql`
  fragment PictureManagementUtils_node on OpenCtiFile {
    id
    name
    description
    order
    inCarousel
  }
`;
