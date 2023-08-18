import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import { GenericAttackCard } from '../../common/cards/GenericAttackCard';

class IntrusionSetCardComponent extends Component {
  render() {
    const { node, bookmarksIds, onLabelClick } = this.props;
    return (
      <GenericAttackCard
        cardData={node}
        cardLink={`/dashboard/threats/intrusion_sets/${node.id}`}
        entityType="Intrusion-Set"
        onLabelClick={onLabelClick}
        bookmarksIds={bookmarksIds}
      />
    );
  }
}

IntrusionSetCardComponent.propTypes = {
  node: PropTypes.object,
  bookmarksIds: PropTypes.array,
  onLabelClick: PropTypes.func,
};

const IntrusionSetCardFragment = createFragmentContainer(
  IntrusionSetCardComponent,
  {
    node: graphql`
      fragment IntrusionSetCard_node on IntrusionSet {
        id
        name
        aliases
        description
        created
        modified
        objectMarking {
          edges {
            node {
              id
              definition_type
              definition
              x_opencti_order
              x_opencti_color
            }
          }
        }
        objectLabel {
          edges {
            node {
              id
              value
              color
            }
          }
        }
        targetedCountries: stixCoreRelationships(
          relationship_type: "targets"
          toTypes: ["Country"]
          first: 5
          orderBy: created_at
          orderMode: desc
        ) {
          edges {
            node {
              to {
                ... on Country {
                  name
                }
              }
            }
          }
        }
        targetedSectors: stixCoreRelationships(
          relationship_type: "targets"
          toTypes: ["Sector"]
          first: 5
          orderBy: created_at
          orderMode: desc
        ) {
          edges {
            node {
              to {
                ... on Sector {
                  name
                }
              }
            }
          }
        }
        usedMalware: stixCoreRelationships(
          relationship_type: "uses"
          toTypes: ["Malware"]
          first: 5
          orderBy: created_at
          orderMode: desc
        ) {
          edges {
            node {
              to {
                ... on Malware {
                  name
                }
              }
            }
          }
        }
      }
    `,
  },
);

const IntrusionSetCard = compose()(IntrusionSetCardFragment);
export default IntrusionSetCard;
