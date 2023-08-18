import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import { GenericAttackCard } from '../../common/cards/GenericAttackCard';

class ThreatActorGroupCardComponent extends Component {
  render() {
    const { node, bookmarksIds, onLabelClick } = this.props;
    return (
      <GenericAttackCard
        cardData={node}
        cardLink={`/dashboard/threats/threat_actors_group/${node.id}`}
        entityType="Threat-Actor-Group"
        onLabelClick={onLabelClick}
        bookmarksIds={bookmarksIds}
      />
    );
  }
}

ThreatActorGroupCardComponent.propTypes = {
  node: PropTypes.object,
  bookmarksIds: PropTypes.array,
  onLabelClick: PropTypes.func,
};

const ThreatActorGroupCardFragment = createFragmentContainer(
  ThreatActorGroupCardComponent,
  {
    node: graphql`
      fragment ThreatActorGroupCard_node on ThreatActorGroup {
        id
        name
        aliases
        description
        created
        modified
        objectLabel {
          edges {
            node {
              id
              value
              color
            }
          }
        }
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

const ThreatActorGroupCard = compose()(ThreatActorGroupCardFragment);
export default ThreatActorGroupCard;
