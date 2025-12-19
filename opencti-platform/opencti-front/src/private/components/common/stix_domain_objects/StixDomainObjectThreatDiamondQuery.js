import { graphql } from 'react-relay';

export const stixDomainObjectThreatDiamondQuery = graphql`
  query StixDomainObjectThreatDiamondQuery($id: String!) {
    ...StixDomainObjectDiamond_data
  }
`;
