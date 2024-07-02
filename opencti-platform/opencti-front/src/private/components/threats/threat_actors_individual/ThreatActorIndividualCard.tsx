import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { ThreatActorIndividualCard_node$key } from './__generated__/ThreatActorIndividualCard_node.graphql';
import { GenericAttack, GenericAttackCard } from '../../common/cards/GenericAttackCard';

export const ThreatActorIndividualCardFragment = graphql`
  fragment ThreatActorIndividualCard_node on ThreatActorIndividual {
    id
    name
    aliases
    description
    created
    modified
    entity_type
    threat_actor_types
    sophistication
    resource_level
    creators {
      id
      name
    }
    avatar {
      id
      name
    }
    status {
      id
      template {
        id
        name
        color
      }
    }
    objectLabel {
      id
      value
      color
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
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
    countryFlag: stixCoreRelationships(
      relationship_type: "located-at"
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
`;
interface ThreatActorIndividualCardProps {
  node: ThreatActorIndividualCard_node$key;
  onLabelClick: () => void;
  bookmarksIds?: string[];
}
const ThreatActorIndividualCard: FunctionComponent<
ThreatActorIndividualCardProps
> = ({ node, onLabelClick, bookmarksIds }) => {
  const data = useFragment(ThreatActorIndividualCardFragment, node);
  return (
    <GenericAttackCard
      cardData={data as GenericAttack}
      cardLink={`/dashboard/threats/threat_actors_individual/${data.id}`}
      entityType="Threat-Actor-Individual"
      onLabelClick={onLabelClick}
      bookmarksIds={bookmarksIds}
    />
  );
};
export default ThreatActorIndividualCard;
