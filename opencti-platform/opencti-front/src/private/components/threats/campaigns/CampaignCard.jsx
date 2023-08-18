import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import { GenericAttackCard } from '../../common/cards/GenericAttackCard';

class CampaignCardComponent extends Component {
  render() {
    const { node, bookmarksIds, onLabelClick } = this.props;
    return (
      <GenericAttackCard
        cardData={node}
        cardLink={`/dashboard/threats/campaigns/${node.id}`}
        entityType="Campaign"
        onLabelClick={onLabelClick}
        bookmarksIds={bookmarksIds}
      />
    );
  }
}

CampaignCardComponent.propTypes = {
  node: PropTypes.object,
  bookmarksIds: PropTypes.array,
  onLabelClick: PropTypes.func,
};

const CampaignCardFragment = createFragmentContainer(CampaignCardComponent, {
  node: graphql`
    fragment CampaignCard_node on Campaign {
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
});

const CampaignCard = compose()(CampaignCardFragment);
export default CampaignCard;
