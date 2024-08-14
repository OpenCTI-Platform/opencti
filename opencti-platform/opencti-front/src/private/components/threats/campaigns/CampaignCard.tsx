import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { GenericAttack, GenericAttackCard } from '../../common/cards/GenericAttackCard';
import { CampaignCard_node$key } from './__generated__/CampaignCard_node.graphql';

export const CampaignCardFragment = graphql`
  fragment CampaignCard_node on Campaign {
    id
    name
    aliases
    entity_type
    description
    created
    modified
    createdBy {
      id
      name
    }
    creators {
      id
      name
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
    targetedCountries: stixCoreRelationships(
      relationship_type: "targets"
      toTypes: ["Country"]
      first: 10
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
      first: 10
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
      first: 10
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
`;

interface CampaignCardProps {
  node: CampaignCard_node$key;
  onLabelClick: () => void;
  bookmarksIds?: string[];
}

const CampaignCard: FunctionComponent<CampaignCardProps> = ({
  node,
  bookmarksIds,
  onLabelClick,
}) => {
  const data = useFragment(CampaignCardFragment, node);
  return (
    <GenericAttackCard
      cardData={data as GenericAttack}
      cardLink={`/dashboard/threats/campaigns/${data.id}`}
      entityType="Campaign"
      onLabelClick={onLabelClick}
      bookmarksIds={bookmarksIds}
    />
  );
};

export default CampaignCard;
