import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { map, filter, head, compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { CheckCircle } from '@mui/icons-material';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import ItemIcon from '../../../../components/ItemIcon';

const styles = (theme) => ({
  avatar: {
    width: 24,
    height: 24,
  },
  icon: {
    color: theme.palette.primary.main,
  },
});

const addLocationsLinesMutationRelationAdd = graphql`
  mutation AddLocationsLinesRelationAddMutation(
    $input: StixCoreRelationshipAddInput
  ) {
    stixCoreRelationshipAdd(input: $input) {
      from {
        ...IntrusionSetLocations_intrusionSet
      }
    }
  }
`;

export const addLocationsMutationRelationDelete = graphql`
  mutation AddLocationsLinesRelationDeleteMutation(
    $fromId: StixRef!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixCoreRelationshipDelete(
      fromId: $fromId
      toId: $toId
      relationship_type: $relationship_type
    )
  }
`;

class AddLocationsLinesContainer extends Component {
  toggleLocation(location) {
    const { intrusionSetId, intrusionSetLocations } = this.props;
    const intrusionSetLocationsIds = map(
      (n) => n.node.id,
      intrusionSetLocations,
    );
    const alreadyAdded = intrusionSetLocationsIds.includes(location.id);
    if (alreadyAdded) {
      const existingLocation = head(
        filter((n) => n.node.id === location.id, intrusionSetLocations),
      );
      commitMutation({
        mutation: addLocationsMutationRelationDelete,
        variables: {
          fromId: intrusionSetId,
          toId: existingLocation.node.id,
          relationship_type: 'originates-from',
        },
        updater: (store) => {
          const node = store.get(intrusionSetId);
          const locations = node.getLinkedRecord('locations');
          const edges = locations.getLinkedRecords('edges');
          const newEdges = filter(
            (n) => n.getLinkedRecord('node').getValue('id')
              !== existingLocation.node.id,
            edges,
          );
          locations.setLinkedRecords(newEdges, 'edges');
        },
      });
    } else {
      const input = {
        relationship_type: 'originates-from',
        fromId: intrusionSetId,
        toId: location.id,
      };
      commitMutation({
        mutation: addLocationsLinesMutationRelationAdd,
        variables: { input },
      });
    }
  }

  render() {
    const { classes, data, intrusionSetLocations } = this.props;
    const intrusionSetLocationsIds = map(
      (n) => n.node.id,
      intrusionSetLocations,
    );
    return (
      <List>
        {data.locations.edges.map((locationNode) => {
          const location = locationNode.node;
          const alreadyAdded = intrusionSetLocationsIds.includes(location.id);
          return (
            <ListItem
              key={location.id}
              classes={{ root: classes.menuItem }}
              divider={true}
              button={true}
              onClick={this.toggleLocation.bind(this, location)}
            >
              <ListItemIcon>
                {alreadyAdded ? (
                  <CheckCircle classes={{ root: classes.icon }} />
                ) : (
                  <ItemIcon type={location.entity_type} />
                )}
              </ListItemIcon>
              <ListItemText
                primary={location.name}
                secondary={truncate(location.description, 120)}
              />
            </ListItem>
          );
        })}
      </List>
    );
  }
}

AddLocationsLinesContainer.propTypes = {
  intrusionSetId: PropTypes.string,
  intrusionSetLocations: PropTypes.array,
  data: PropTypes.object,
  classes: PropTypes.object,
};

export const addLocationsLinesQuery = graphql`
  query AddLocationsLinesQuery($search: String, $count: Int!, $cursor: ID) {
    ...AddLocationsLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddLocationsLines = createPaginationContainer(
  AddLocationsLinesContainer,
  {
    data: graphql`
      fragment AddLocationsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        locations(search: $search, first: $count, after: $cursor)
          @connection(key: "Pagination_locations") {
          edges {
            node {
              id
              entity_type
              name
              description
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.locations;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: addLocationsLinesQuery,
  },
);

export default compose(inject18n, withStyles(styles))(AddLocationsLines);
