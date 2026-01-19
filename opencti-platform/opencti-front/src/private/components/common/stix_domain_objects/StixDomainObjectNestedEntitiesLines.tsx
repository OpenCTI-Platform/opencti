import React, { CSSProperties } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { ListItemButton } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import { DraftChip } from '../draft/DraftChip';
import ItemIcon from '../../../../components/ItemIcon';
import StixNestedRefRelationshipPopover from '../stix_nested_ref_relationships/StixNestedRefRelationshipPopover';
import { resolveLink } from '../../../../utils/Entity';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import ItemEntityType from '../../../../components/ItemEntityType';
import { useFormatter } from '../../../../components/i18n';
import { useTheme } from '@mui/material/styles';
import {
  StixDomainObjectNestedEntitiesLinesQuery,
  StixDomainObjectNestedEntitiesLinesQuery$variables,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectNestedEntitiesLinesQuery.graphql';
import { StixDomainObjectNestedEntitiesLines_data$key } from '@components/common/stix_domain_objects/__generated__/StixDomainObjectNestedEntitiesLines_data.graphql';

export const stixDomainObjectNestedEntitiesLinesQuery = graphql`
  query StixDomainObjectNestedEntitiesLinesQuery(
    $fromOrToId: String
    $search: String
    $count: Int!
    $orderBy: StixRefRelationshipsOrdering
    $orderMode: OrderingMode
  ) {
    ...StixDomainObjectNestedEntitiesLines_data
    @arguments(
      fromOrToId: $fromOrToId
      search: $search
      count: $count
      orderBy: $orderBy
      orderMode: $orderMode
    )
  }
`;

const StixDomainObjectNestedEntitiesLinesFragment = graphql`
  fragment StixDomainObjectNestedEntitiesLines_data on Query
  @argumentDefinitions(
    fromOrToId: { type: "String" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    orderBy: { type: "StixRefRelationshipsOrdering" }
    orderMode: { type: "OrderingMode" }
  ) {
    stixNestedRefRelationships(
      fromOrToId: $fromOrToId
      search: $search
      first: $count
      orderBy: $orderBy
      orderMode: $orderMode
    ) @connection(key: "Pagination_stixNestedRefRelationships") {
      edges {
        node {
          id
          relationship_type
          start_time
          stop_time
          from {
            ... on BasicObject {
              id
              entity_type
              parent_types
            }
            ... on StixObject {
              draftVersion {
                draft_id
                draft_operation
              }
              created_at
              updated_at
            }
            ... on AttackPattern {
              name
              description
            }
            ... on Campaign {
              name
              description
            }
            ... on CourseOfAction {
              name
              description
            }
            ... on Individual {
              name
              description
            }
            ... on Organization {
              name
              description
            }
            ... on Sector {
              name
              description
            }
            ... on System {
              name
              description
            }
            ... on Indicator {
              name
            }
            ... on Infrastructure {
              name
            }
            ... on IntrusionSet {
              name
              description
            }
            ... on Position {
              name
              description
            }
            ... on City {
              name
              description
            }
            ... on AdministrativeArea {
              name
              description
            }
            ... on Country {
              name
              description
            }
            ... on Region {
              name
              description
            }
            ... on Malware {
              name
              description
            }
            ... on MalwareAnalysis {
              result_name
            }
            ... on ThreatActor {
              name
              description
            }
            ... on Tool {
              name
              description
            }
            ... on Vulnerability {
              name
              description
            }
            ... on Incident {
              name
              description
            }
            ... on Event {
              name
              description
            }
            ... on Channel {
              name
              description
            }
            ... on Narrative {
              name
              description
            }
            ... on Language {
              name
            }
            ... on DataComponent {
              name
            }
            ... on DataSource {
              name
            }
            ... on Case {
              name
            }
            ... on StixCyberObservable {
              observable_value
            }
          }
          to {
            ... on BasicObject {
              id
              entity_type
              parent_types
            }
            ... on StixObject {
              draftVersion {
                draft_id
                draft_operation
              }
              created_at
              updated_at
            }
            ... on AttackPattern {
              name
              description
            }
            ... on Campaign {
              name
              description
            }
            ... on CourseOfAction {
              name
              description
            }
            ... on Individual {
              name
              description
            }
            ... on Organization {
              name
              description
            }
            ... on Sector {
              name
              description
            }
            ... on System {
              name
              description
            }
            ... on Indicator {
              name
            }
            ... on Infrastructure {
              name
            }
            ... on IntrusionSet {
              name
              description
            }
            ... on Position {
              name
              description
            }
            ... on City {
              name
              description
            }
            ... on AdministrativeArea {
              name
              description
            }
            ... on Country {
              name
              description
            }
            ... on Region {
              name
              description
            }
            ... on Malware {
              name
              description
            }
            ... on MalwareAnalysis {
              result_name
            }
            ... on ThreatActor {
              name
              description
            }
            ... on Tool {
              name
              description
            }
            ... on Vulnerability {
              name
              description
            }
            ... on Incident {
              name
              description
            }
            ... on Event {
              name
              description
            }
            ... on Channel {
              name
              description
            }
            ... on Narrative {
              name
              description
            }
            ... on Language {
              name
            }
            ... on DataComponent {
              name
            }
            ... on DataSource {
              name
            }
            ... on Case {
              name
            }
            ... on StixCyberObservable {
              observable_value
            }
          }
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

interface StixDomainObjectNestedEntitiesLinesProps {
  stixDomainObjectId: string;
  paginationOptions: StixDomainObjectNestedEntitiesLinesQuery$variables;
  queryRef: PreloadedQuery<StixDomainObjectNestedEntitiesLinesQuery>;
}

const StixDomainObjectNestedEntitiesLines = ({
  stixDomainObjectId,
  paginationOptions,
  queryRef,
}: StixDomainObjectNestedEntitiesLinesProps) => {
  const theme = useTheme();
  const { fsd } = useFormatter();
  const queryData = usePreloadedQuery<StixDomainObjectNestedEntitiesLinesQuery>(stixDomainObjectNestedEntitiesLinesQuery, queryRef);
  const data = useFragment<StixDomainObjectNestedEntitiesLines_data$key>(
    StixDomainObjectNestedEntitiesLinesFragment,
    queryData,
  );
  const stixNestedObjectsNodes = data?.stixNestedRefRelationships?.edges.filter((e) => {
    const stixCoreObject = e.node.from?.id === stixDomainObjectId ? e.node.to : e.node.from;
    return stixCoreObject;
  });
  const bodyItemStyle: CSSProperties = {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  };
  return (
    <div>
      {stixNestedObjectsNodes
        && stixNestedObjectsNodes.map((edge) => {
          const { node } = edge;
          const stixCoreObject = (node.from?.id === stixDomainObjectId ? node.to : node.from)!;
          const link = `${resolveLink(stixCoreObject.entity_type)}/${stixCoreObject.id}`;
          return (
            <ListItem
              key={stixCoreObject.id}
              divider={true}
              disablePadding
              secondaryAction={(
                <StixNestedRefRelationshipPopover
                  stixNestedRefRelationshipId={node.id}
                  paginationOptions={paginationOptions}
                />
              )}
            >
              <ListItemButton
                style={{
                  paddingLeft: 10,
                  height: 50,
                }}
                component={Link}
                to={link}
              >
                <ListItemIcon
                  style={{
                    color: theme.palette.primary.main,
                  }}
                >
                  <ItemIcon type={stixCoreObject.entity_type} />
                </ListItemIcon>
                <ListItemText
                  primary={(
                    <div>
                      <div
                        style={{ ...bodyItemStyle, width: '20%' }}
                      >
                        <ItemEntityType
                          entityType={node.relationship_type}
                        />
                      </div>
                      <div
                        style={{ ...bodyItemStyle, width: '20%' }}
                      >
                        <ItemEntityType
                          entityType={stixCoreObject.entity_type ?? '-'}
                          showIcon
                        />
                      </div>
                      <div
                        style={{ ...bodyItemStyle, width: '40%' }}
                      >
                        {getMainRepresentative(stixCoreObject)}
                        {stixCoreObject.draftVersion && (<DraftChip />)}
                      </div>
                      <div
                        style={bodyItemStyle}
                      >
                        {fsd(node.start_time)}
                      </div>
                    </div>
                  )}
                />
              </ListItemButton>
            </ListItem>
          );
        })}
    </div>
  );
};

export default StixDomainObjectNestedEntitiesLines;
