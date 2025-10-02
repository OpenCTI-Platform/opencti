import React from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import List from '@mui/material/List';
import SimpleStixObjectOrStixRelationshipStixCoreRelationshipLine from './SimpleStixObjectOrStixRelationshipStixCoreRelationshipLine';
import {
  SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesPaginationQuery,
  SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesPaginationQuery$variables,
} from './__generated__/SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesPaginationQuery.graphql';
import { SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines_data$key } from './__generated__/SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines_data.graphql';
import { useFormatter } from '../../../../components/i18n';
import { NO_DATA_WIDGET_MESSAGE } from '../../../../components/dashboard/WidgetNoData';
import { DataColumns } from '../../../../components/list_lines';

const SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesFragment = graphql`
  fragment SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines_data on Query
  @argumentDefinitions(
    fromOrToId: { type: "[String]!" }
    relationship_type: { type: "[String]" }
    startTimeStart: { type: "DateTime" }
    startTimeStop: { type: "DateTime" }
    stopTimeStart: { type: "DateTime" }
    stopTimeStop: { type: "DateTime" }
    confidences: { type: "[Int]" }
    orderBy: {
      type: "StixCoreRelationshipsOrdering"
      defaultValue: created_at
    }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
  ) {
    stixCoreRelationships(
      fromOrToId: $fromOrToId
      relationship_type: $relationship_type
      startTimeStart: $startTimeStart
      startTimeStop: $startTimeStop
      stopTimeStart: $stopTimeStart
      stopTimeStop: $stopTimeStop
      confidences: $confidences
      orderBy: $orderBy
      orderMode: $orderMode
      first: $count
      after: $cursor
    ) @connection(key: "Pagination_stixCoreRelationships") {
      edges {
        node {
          ...SimpleStixObjectOrStixRelationshipStixCoreRelationshipLine_node
        }
      }
    }
  }
`;

export const simpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesQuery = graphql`
  query SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesPaginationQuery(
    $fromOrToId: [String]!
    $relationship_type: [String]
    $startTimeStart: DateTime
    $startTimeStop: DateTime
    $stopTimeStart: DateTime
    $stopTimeStop: DateTime
    $confidences: [Int]
    $orderBy: StixCoreRelationshipsOrdering
    $orderMode: OrderingMode
    $count: Int!
    $cursor: ID
  ) {
    ...SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines_data
    @arguments(
      fromOrToId: $fromOrToId
      relationship_type: $relationship_type
      startTimeStart: $startTimeStart
      startTimeStop: $startTimeStop
      stopTimeStart: $stopTimeStart
      stopTimeStop: $stopTimeStop
      confidences: $confidences
      orderBy: $orderBy
      orderMode: $orderMode
      count: $count
      cursor: $cursor
    )
  }
`;

interface SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesProps {
  queryRef: PreloadedQuery<SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesPaginationQuery>,
  dataColumns: DataColumns,
  stixObjectOrStixRelationshipId: string,
  stixObjectOrStixRelationshipLink: string,
  paginationOptions: SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesPaginationQuery$variables,
}

const SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines = ({
  queryRef,
  dataColumns,
  stixObjectOrStixRelationshipId,
  stixObjectOrStixRelationshipLink,
  paginationOptions,
}: SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesProps) => {
  const { t_i18n } = useFormatter();
  const queryResult = usePreloadedQuery(simpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesQuery, queryRef);
  const data = useFragment<SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines_data$key>(
    SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesFragment,
    queryResult,
  );

  return (
    <div style={{ height: '100%' }}>
      {data.stixCoreRelationships && data.stixCoreRelationships.edges.length > 0 ? (
        <List>
          {data.stixCoreRelationships.edges.map(
            (stixCoreRelationshipEdge, index) => {
              const stixCoreRelationship = stixCoreRelationshipEdge.node;
              return (
                <SimpleStixObjectOrStixRelationshipStixCoreRelationshipLine
                  key={`${stixObjectOrStixRelationshipId}_${index}`}
                  dataColumns={dataColumns}
                  entityId={stixObjectOrStixRelationshipId}
                  entityLink={stixObjectOrStixRelationshipLink}
                  paginationOptions={paginationOptions}
                  node={stixCoreRelationship}
                  connectionKey="Pagination_stixCoreRelationships"
                />
              );
            },
          )}
        </List>
      ) : (
        <div
          style={{
            display: 'table',
            height: '100%',
            width: '100%',
            paddingTop: 15,
            paddingBottom: 15,
          }}
        >
          <span
            style={{
              display: 'table-cell',
              verticalAlign: 'middle',
              textAlign: 'center',
            }}
          >
            {t_i18n(NO_DATA_WIDGET_MESSAGE)}
          </span>
        </div>
      )}
    </div>
  );
};

export default SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines;
