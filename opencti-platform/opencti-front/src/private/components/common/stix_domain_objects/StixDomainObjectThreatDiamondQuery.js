import { graphql } from 'react-relay';

// oxlint-disable-next-line import/prefer-default-export
export const stixDomainObjectThreatDiamondQuery = graphql`
  query StixDomainObjectThreatDiamondQuery($id: String!) {
    ...StixDomainObjectDiamond_data
  }
`;
