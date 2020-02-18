import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import {
  map, filter, head, compose,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { CheckCircle, Domain } from '@material-ui/icons';
import graphql from 'babel-plugin-relay/macro';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';

const styles = (theme) => ({
  avatar: {
    width: 24,
    height: 24,
  },
  icon: {
    color: theme.palette.primary.main,
  },
});

const addSubSectorsLinesMutationRelationAdd = graphql`
  mutation AddSubSectorsLinesRelationAddMutation(
    $input: StixRelationAddInput!
  ) {
    stixRelationAdd(input: $input) {
      to {
        ...SectorSubSectors_sector
      }
    }
  }
`;

export const addSubSectorsMutationRelationDelete = graphql`
  mutation AddSubSectorsLinesRelationDeleteMutation($id: ID!) {
    stixRelationEdit(id: $id) {
      delete
    }
  }
`;

class AddSubSectorsLinesContainer extends Component {
  toggleSubSector(subSector) {
    const { sectorId, sectorSubSectors } = this.props;
    const sectorSubSectorsIds = map((n) => n.node.id, sectorSubSectors);
    const alreadyAdded = sectorSubSectorsIds.includes(subSector.id);

    if (alreadyAdded) {
      const existingSubSector = head(
        filter((n) => n.node.id === subSector.id, sectorSubSectors),
      );
      commitMutation({
        mutation: addSubSectorsMutationRelationDelete,
        variables: { id: existingSubSector.relation.id },
        updater: (store) => {
          const node = store.get(this.props.sectorId);
          const subSectors = node.getLinkedRecord('subSectors');
          const edges = subSectors.getLinkedRecords('edges');
          const newEdges = filter(
            (n) => n.getLinkedRecord('node').getValue('id') !== existingSubSector.node.id,
            edges,
          );
          subSectors.setLinkedRecords(newEdges, 'edges');
        },
      });
    } else {
      const input = {
        relationship_type: 'gathering',
        fromId: subSector.id,
        fromRole: 'part_of',
        toId: sectorId,
        toRole: 'gather',
      };
      commitMutation({
        mutation: addSubSectorsLinesMutationRelationAdd,
        variables: { input },
      });
    }
  }

  render() {
    const { classes, data, sectorSubSectors } = this.props;
    const sectorSubSectorsIds = map((n) => n.node.id, sectorSubSectors);
    return (
      <List>
        {data.sectors.edges.map((sectorNode) => {
          const sector = sectorNode.node;
          const alreadyAdded = sectorSubSectorsIds.includes(sector.id);
          return (
            <ListItem
              key={sector.id}
              classes={{ root: classes.menuItem }}
              divider={true}
              button={true}
              onClick={this.toggleSubSector.bind(this, sector)}
            >
              <ListItemIcon>
                {alreadyAdded ? (
                  <CheckCircle classes={{ root: classes.icon }} />
                ) : (
                  <Domain classes={{ root: classes.icon }} />
                )}
              </ListItemIcon>
              <ListItemText
                primary={sector.name}
                secondary={truncate(sector.description, 120)}
              />
            </ListItem>
          );
        })}
      </List>
    );
  }
}

AddSubSectorsLinesContainer.propTypes = {
  sectorId: PropTypes.string,
  sectorSubSectors: PropTypes.array,
  data: PropTypes.object,
  classes: PropTypes.object,
};

export const addSubSectorsLinesQuery = graphql`
  query AddSubSectorsLinesQuery($search: String, $count: Int!, $cursor: ID) {
    ...AddSubSectorsLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddSubSectorsLines = createPaginationContainer(
  AddSubSectorsLinesContainer,
  {
    data: graphql`
      fragment AddSubSectorsLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
        ) {
        sectors(search: $search, first: $count, after: $cursor)
          @connection(key: "Pagination_sectors") {
          edges {
            node {
              id
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
      return props.data && props.data.subSectors;
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
    query: addSubSectorsLinesQuery,
  },
);

export default compose(inject18n, withStyles(styles))(AddSubSectorsLines);
