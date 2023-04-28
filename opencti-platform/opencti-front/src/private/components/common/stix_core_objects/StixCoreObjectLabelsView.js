import React from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import inject18n from '../../../../components/i18n';
import StixCoreObjectOrCoreRelationshipLabelsView
  from '../stix_core_objects_or_stix_relationships/StixCoreObjectOrCoreRelationshipLabelsView';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

const stixCoreObjectMutationRelationsAdd = graphql`
  mutation StixCoreObjectLabelsViewRelationsAddMutation(
    $id: ID!
    $input: StixRefRelationshipsAddInput!
    $commitMessage: String
    $references: [String]
  ) {
    stixCoreObjectEdit(id: $id) {
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

const stixCoreObjectMutationRelationDelete = graphql`
  mutation StixCoreObjectLabelsViewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
    $commitMessage: String
    $references: [String]
  ) {
    stixCoreObjectEdit(id: $id) {
      relationDelete(
        toId: $toId
        relationship_type: $relationship_type
        commitMessage: $commitMessage
        references: $references
      ) {
        ... on StixCoreObject {
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

const StixCoreObjectLabelsView = (props) => {
  return <StixCoreObjectOrCoreRelationshipLabelsView {...props}
                                                     mutationRelationsAdd={stixCoreObjectMutationRelationsAdd}
                                                     mutationRelationDelete={stixCoreObjectMutationRelationDelete}
                                                     enableReferences={useIsEnforceReference(props.entity_type)}/>;
};

StixCoreObjectLabelsView.propTypes = {
  classes: PropTypes.object.isRequired,
  t: PropTypes.func,
  id: PropTypes.string,
  labels: PropTypes.object,
};

export default compose(inject18n)(StixCoreObjectLabelsView);
