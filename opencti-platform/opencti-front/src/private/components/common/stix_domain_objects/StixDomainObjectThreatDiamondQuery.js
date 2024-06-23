import { graphql } from 'react-relay';

// eslint-disable-next-line import/prefer-default-export
export const stixDomainObjectThreatDiamondQuery = graphql`
  query StixDomainObjectThreatDiamondQuery($id: String!) {
    ...StixDomainObjectDiamond_data
  }
`;
