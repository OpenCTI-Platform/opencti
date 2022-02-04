// import React, { Component } from 'react';
// import * as PropTypes from 'prop-types';
// import { createPaginationContainer } from 'react-relay';
// import {
//   map, filter, head, compose,
// } from 'ramda';
// import { withStyles } from '@material-ui/core/styles';
// import List from '@material-ui/core/List';
// import ListItem from '@material-ui/core/ListItem';
// import ListItemIcon from '@material-ui/core/ListItemIcon';
// import ListItemText from '@material-ui/core/ListItemText';
// import { CheckCircle } from '@material-ui/icons';
// import graphql from 'babel-plugin-relay/macro';
// import { truncate } from '../../../../utils/String';
// import inject18n from '../../../../components/i18n';
// import { commitMutation } from '../../../../relay/environment';
// import ItemIcon from '../../../../components/ItemIcon';

// const styles = (theme) => ({
//   avatar: {
//     width: 24,
//     height: 24,
//   },
//   icon: {
//     color: theme.palette.primary.main,
//   },
// });

// const addLocationsLinesMutationRelationAdd = graphql`
//   mutation AddLocationsLinesRelationAddMutation(
//     $input: StixCoreRelationshipAddInput
//   ) {
//     stixCoreRelationshipAdd(input: $input) {
//       from {
//         ...NetworkLocations_networkSet
//       }
//     }
//   }
// `;

// export const addLocationsMutationRelationDelete = graphql`
//   mutation AddLocationsLinesRelationDeleteMutation(
//     $fromId: String!
//     $toId: String!
//     $relationship_type: String!
//   ) {
//     stixCoreRelationshipDelete(
//       fromId: $fromId
//       toId: $toId
//       relationship_type: $relationship_type
//     )
//   }
// `;

// class AddLocationsLinesContainer extends Component {
//   toggleLocation(location) {
//     const { networkId, networkLocations } = this.props;
//     const networkLocationsIds = map(
//       (n) => n.node.id,
//       networkLocations,
//     );
//     const alreadyAdded = networkLocationsIds.includes(location.id);
//     if (alreadyAdded) {
//       const existingLocation = head(
//         filter((n) => n.node.id === location.id, networkLocations),
//       );
//       commitMutation({
//         mutation: addLocationsMutationRelationDelete,
//         variables: {
//           fromId: networkId,
//           toId: existingLocation.node.id,
//           relationship_type: 'originates-from',
//         },
//         updater: (store) => {
//           const node = store.get(networkId);
//           const locations = node.getLinkedRecord('locations');
//           const edges = locations.getLinkedRecords('edges');
//           const newEdges = filter(
//             (n) => n.getLinkedRecord('node').getValue('id')
//               !== existingLocation.node.id,
//             edges,
//           );
//           locations.setLinkedRecords(newEdges, 'edges');
//         },
//       });
//     } else {
//       const input = {
//         relationship_type: 'originates-from',
//         fromId: networkId,
//         toId: location.id,
//       };
//       commitMutation({
//         mutation: addLocationsLinesMutationRelationAdd,
//         variables: { input },
//       });
//     }
//   }

//   render() {
//     const { classes, data, networkLocations } = this.props;
//     const networkLocationsIds = map(
//       (n) => n.node.id,
//       networkLocations,
//     );
//     return (
//       <List>
//         {data.locations.edges.map((locationNode) => {
//           const location = locationNode.node;
//           const alreadyAdded = networkLocationsIds.includes(location.id);
//           return (
//             <ListItem
//               key={location.id}
//               classes={{ root: classes.menuItem }}
//               divider={true}
//               button={true}
//               onClick={this.toggleLocation.bind(this, location)}
//             >
//               <ListItemIcon>
//                 {alreadyAdded ? (
//                   <CheckCircle classes={{ root: classes.icon }} />
//                 ) : (
//                   <ItemIcon type={location.entity_type} />
//                 )}
//               </ListItemIcon>
//               <ListItemText
//                 primary={location.name}
//                 secondary={truncate(location.description, 120)}
//               />
//             </ListItem>
//           );
//         })}
//       </List>
//     );
//   }
// }

// AddLocationsLinesContainer.propTypes = {
//   networkId: PropTypes.string,
//   networkLocations: PropTypes.array,
//   data: PropTypes.object,
//   classes: PropTypes.object,
// };

// export const addLocationsLinesQuery = graphql`
//   query AddLocationsLinesQuery($search: String, $count: Int!, $cursor: ID) {
//     ...AddLocationsLines_data
//       @arguments(search: $search, count: $count, cursor: $cursor)
//   }
// `;

// const AddLocationsLines = createPaginationContainer(
//   AddLocationsLinesContainer,
//   {
//     data: graphql`
//       fragment AddLocationsLines_data on Query
//       @argumentDefinitions(
//         search: { type: "String" }
//         count: { type: "Int", defaultValue: 25 }
//         cursor: { type: "ID" }
//       ) {
//         locations(search: $search, limit: $count, after: $cursor)
//           @connection(key: "Pagination_locations") {
//           edges {
//             node {
//               id
//               entity_type
//               name
//               description
//             }
//           }
//         }
//       }
//     `,
//   },
//   {
//     direction: 'forward',
//     getConnectionFromProps(props) {
//       return props.data && props.data.locations;
//     },
//     getFragmentVariables(prevVars, totalCount) {
//       return {
//         ...prevVars,
//         count: totalCount,
//       };
//     },
//     getVariables(props, { count, cursor }, fragmentVariables) {
//       return {
//         count,
//         cursor,
//         orderBy: fragmentVariables.orderBy,
//         orderMode: fragmentVariables.orderMode,
//       };
//     },
//     query: addLocationsLinesQuery,
//   },
// );

// export default compose(inject18n, withStyles(styles))(AddLocationsLines);
