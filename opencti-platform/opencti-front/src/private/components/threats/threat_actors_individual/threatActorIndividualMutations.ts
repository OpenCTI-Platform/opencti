import { graphql } from 'relay-runtime';

export const scoRelationshipAdd = graphql`
  mutation threatActorIndividualMutationsRelationshipAddMutation(
    $input: StixCoreRelationshipAddInput
  ) {
    stixCoreRelationshipAdd(input: $input) {
      from {
        ... on ThreatActorIndividual {
          id
          stixCoreRelationships {
            edges {
              node {
                id
                fromId
                toId
                entity_type
                relationship_type
              }
            }
          }
        }
      }
      to {
        ... on Individual {
          id
        }
      }
    }
  }
`;

export const scoRelationshipDelete = graphql`
  mutation threatActorIndividualMutationsRelationshipDeleteMutation(
    $fromId: StixRef!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixCoreRelationshipDelete(
      fromId: $fromId,
      toId: $toId,
      relationship_type: $relationship_type
    )
  }
`;
