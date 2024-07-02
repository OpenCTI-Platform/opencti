import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { GenericAttack, GenericAttackCard } from '../../common/cards/GenericAttackCard';
import { IntrusionSetCard_node$key } from './__generated__/IntrusionSetCard_node.graphql';

export const IntrusionSetCardFragment = graphql`
  fragment IntrusionSetCard_node on IntrusionSet {
    id
    name
    aliases
    entity_type
    description
    created
    modified
    primary_motivation
    secondary_motivations
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
    avatar {
      id
      name
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
    countryFlag: stixCoreRelationships(
      relationship_type: "originates-from"
      toTypes: ["Country"]
      first: 1
      orderBy: created_at
      orderMode: desc
    ) {
      edges {
        node {
          to {
            ... on Country {
              name
              x_opencti_aliases
            }
          }
        }
      }
    }
  }
`;

interface IntrusionSetCardProps {
  node: IntrusionSetCard_node$key;
  onLabelClick: () => void;
  bookmarksIds?: string[];
}
const IntrusionSetCard: FunctionComponent<IntrusionSetCardProps> = ({
  node,
  bookmarksIds,
  onLabelClick,
}) => {
  const data = useFragment(IntrusionSetCardFragment, node);
  return (
    <GenericAttackCard
      cardData={data as GenericAttack}
      cardLink={`/dashboard/threats/intrusion_sets/${data.id}`}
      entityType="Intrusion-Set"
      onLabelClick={onLabelClick}
      bookmarksIds={bookmarksIds}
    />
  );
};

export default IntrusionSetCard;
