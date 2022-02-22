import { graphql } from 'react-relay';

// eslint-disable-next-line import/prefer-default-export
export const stixDomainObjectThreatKnowledgeStixRelationshipsQuery = graphql`
  query StixDomainObjectThreatKnowledgeQueryStixRelationshipsQuery(
    $elementId: String
    $elementWithTargetTypes: [String]
    $relationship_type: [String]
    $first: Int
    $orderBy: StixRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: [StixRelationshipsFiltering]
  ) {
    ...StixDomainObjectGlobalKillChain_data
    ...StixDomainObjectTimeline_data
  }
`;
