import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { map, filter, head, compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { CheckCircle, Domain } from '@mui/icons-material';
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
    $input: StixCoreRelationshipAddInput
  ) {
    stixCoreRelationshipAdd(input: $input) {
      to {
        ...SectorSubSectors_sector
      }
    }
  }
`;

export const addSubSectorsMutationRelationDelete = graphql`
  mutation AddSubSectorsLinesRelationDeleteMutation(
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
        variables: {
          fromId: existingSubSector.node.id,
          toId: sectorId,
          relationship_type: 'part-of',
        },
        updater: (store) => {
          const node = store.get(this.props.sectorId);
          const subSectors = node.getLinkedRecord('subSectors');
          const edges = subSectors.getLinkedRecords('edges');
          const newEdges = filter(
            (n) => n.getLinkedRecord('node').getValue('id')
              !== existingSubSector.node.id,
            edges,
          );
          subSectors.setLinkedRecords(newEdges, 'edges');
        },
      });
    } else {
      const input = {
        relationship_type: 'part-of',
        fromId: subSector.id,
        toId: sectorId,
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
                  <Domain />
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
