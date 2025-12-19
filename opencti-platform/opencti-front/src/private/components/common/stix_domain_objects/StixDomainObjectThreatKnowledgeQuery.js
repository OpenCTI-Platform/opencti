import { graphql } from 'react-relay';

export const stixDomainObjectThreatKnowledgeStixRelationshipsQuery = graphql`
  query StixDomainObjectThreatKnowledgeQueryStixRelationshipsQuery(
    $fromOrToId: String
    $elementWithTargetTypes: [String]
    $relationship_type: [String]
    $first: Int
    $orderBy: StixRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...StixDomainObjectGlobalKillChain_data
    ...StixDomainObjectTimeline_data
  }
`;
