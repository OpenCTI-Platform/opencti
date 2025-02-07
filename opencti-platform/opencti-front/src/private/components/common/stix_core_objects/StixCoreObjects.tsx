import React, { FunctionComponent } from 'react';

// export const stixCoreObjectsFragment = graphql`
//   fragment AllStixCoreObjectsDistribution on StixCoreObject {
//     stixCoreObjectsDistribution(
//         field: "entity_type",
//         operation: count,
//     ) {
//         label
//         value
//     }
//   }
// `;
//
// const StixCoreObjectsDistributionQuery = graphql`
//   query AllStixCoreObjectsDistributionPaginationQuery(
//     $search: String
//     $count: Int!
//     $cursor: ID
//     $orderBy: StixCoreRelationshipsOrdering
//     $orderMode: OrderingMode
//     $filters: FilterGroup
//   ) {
//     ...StixCoreObjectsDistribution_data
//     @arguments(
//       search: $search
//       count: $count
//       cursor: $cursor
//       orderBy: $orderBy
//       orderMode: $orderMode
//       filters: $filters
//     )
//   }
// `;
//
// export const StixCoreObjectsDistributionFragment = graphql`
//   fragment StixCoreObjectsDistribution_data on Query
//   @argumentDefinitions(
//     search: { type: "String" }
//     count: { type: "Int", defaultValue: 25 }
//     cursor: { type: "ID" }
//     orderBy: {
//       type: "StixCoreRelationshipsOrdering"
//       defaultValue: created
//     }
//     orderMode: { type: "OrderingMode", defaultValue: desc }
//     filters: { type: "FilterGroup" }
//   )
//   @refetchable(queryName: "StixCoreRelationshipsLinesRefetchQuery") {
//     stixCoreRelationships(
//       search: $search
//       first: $count
//       after: $cursor
//       orderBy: $orderBy
//       orderMode: $orderMode
//       filters: $filters
//     ) @connection(key: "Pagination_stixCoreRelationships") {
//       edges {
//         node {
//           id
//           entity_type
//           created_at
//           draftVersion{
//             draft_id
//             draft_operation
//           }
//           createdBy {
//             ... on Identity {
//             name
//             }
//           }
//             objectMarking {
//               id
//               definition_type
//               definition
//               x_opencti_order
//               x_opencti_color
//             }
//             ...StixCoreObjectsDistribution_data
//         }
//       }
//       `;

interface StixCoreObjectsProps {
  entityId: string;
  stixDomainObjectType: string;
  stixDomainObjectName?: string;
}

const StixCoreObjects: FunctionComponent<StixCoreObjectsProps> = (
  {
    entityId,
    stixDomainObjectType,
    stixDomainObjectName,
  },
) => {
  // const [queryRef, loadQuery] = useQueryLoader(
  //   StixCoreObjectsDistributionQuery,
  // );
  return (
    <>NEW VIEW</>
  );
};

export default StixCoreObjects;
