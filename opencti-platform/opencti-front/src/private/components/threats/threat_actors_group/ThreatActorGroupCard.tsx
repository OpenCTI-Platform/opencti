import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { GenericAttackCard } from '../../common/cards/GenericAttackCard';
import {
  ThreatActorGroupCard_node$key,
} from './__generated__/ThreatActorGroupCard_node.graphql';

const ThreatActorGroupCardFragment = graphql`
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
      }
`;

interface ThreatActorGroupCardProps {
  node: ThreatActorGroupCard_node$key;
  onLabelClick: () => void;
  bookmarksIds?: string[];
}
const ThreatActorGroupCard: FunctionComponent<ThreatActorGroupCardProps> = ({
  node,
  onLabelClick,
  bookmarksIds,
}) => {
  const data = useFragment(ThreatActorGroupCardFragment, node);
  return (
    <GenericAttackCard
      cardData={data}
      cardLink={`/dashboard/threats/threat_actors_group/${data.id}`}
      entityType="Threat-Actor-Group"
      onLabelClick={onLabelClick}
      bookmarksIds={bookmarksIds}
    />
  );
};

export default ThreatActorGroupCard;
