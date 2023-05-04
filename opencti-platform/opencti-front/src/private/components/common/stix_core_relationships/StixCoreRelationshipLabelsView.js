import React from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import StixCoreObjectOrCoreRelationshipLabelsView
  from '../stix_core_objects_or_stix_relationships/StixCoreObjectOrCoreRelationshipLabelsView';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

const stixCoreRelationshipMutationRelationsAdd = graphql`
  mutation StixCoreRelationshipLabelsViewRelationsAddMutation(
    $id: ID!
    $input: StixRefRelationshipsAddInput!
    $commitMessage: String
    $references: [String]
  ) {
    stixCoreRelationshipEdit(id: $id) {
      relationsAdd(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        objectLabel {
          edges {
            node {
              id
              value
              color
            }
          }
        }
      }
    }
  }
`;

const stixCoreRelationshipMutationRelationsDelete = graphql`
  mutation StixCoreRelationshipLabelsViewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
    $commitMessage: String
    $references: [String]
  ) {
    stixCoreRelationshipEdit(id: $id) {
      relationDelete(
        toId: $toId
        relationship_type: $relationship_type
        commitMessage: $commitMessage
        references: $references
      ) {
        ... on StixCoreRelationship {
          objectLabel {
            edges {
              node {
                id
                value
                color
              }
            }
          }
        }
      }
    }
  }
`;

const StixCoreRelationshipLabelsView = (props) => {
  return <StixCoreObjectOrCoreRelationshipLabelsView {...props}
                                                     mutationRelationsAdd={stixCoreRelationshipMutationRelationsAdd}
                                                     mutationRelationDelete={stixCoreRelationshipMutationRelationsDelete}
                                                     enableReferences={useIsEnforceReference('stix-core-relationship')}/>;
};

StixCoreRelationshipLabelsView.propTypes = {
  id: PropTypes.string,
  labels: PropTypes.object,
};

export default StixCoreRelationshipLabelsView;
