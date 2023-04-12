import React from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import inject18n from '../../../../components/i18n';
import StixCoreObjectOrCoreRelationshipLabelsView
  from '../../common/stix_core_objects_or_stix_relationships/StixCoreObjectOrCoreRelationshipLabelsView';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

const stixSightingRelationshipMutationRelationsAdd = graphql`
  mutation StixSightingRelationshipLabelsViewRelationsAddMutation(
    $id: ID!
    $input: StixRefRelationshipsAddInput!
    $commitMessage: String
    $references: [String]
  ) {
    stixSightingRelationshipEdit(id: $id) {
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

const stixSightingRelationshipMutationRelationsDelete = graphql`
  mutation StixSightingRelationshipLabelsViewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
    $commitMessage: String
    $references: [String]
  ) {
    stixSightingRelationshipEdit(id: $id) {
      relationDelete(
        toId: $toId
        relationship_type: $relationship_type
        commitMessage: $commitMessage
        references: $references
      ) {
        ... on StixSightingRelationship {
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

const StixSightingRelationshipLabelsView = (props) => {
  return <StixCoreObjectOrCoreRelationshipLabelsView {...props}
                                                     mutationRelationAdd={stixSightingRelationshipMutationRelationsAdd}
                                                     mutationRelationDelete={stixSightingRelationshipMutationRelationsDelete}
                                                     enableReferences={useIsEnforceReference('stix-sighting-relationship')}/>;
};

StixSightingRelationshipLabelsView.propTypes = {
  classes: PropTypes.object.isRequired,
  t: PropTypes.func,
  id: PropTypes.string,
  labels: PropTypes.object,
};

export default compose(inject18n)(StixSightingRelationshipLabelsView);
