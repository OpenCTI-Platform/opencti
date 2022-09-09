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
import { HexagonOutline } from 'mdi-material-ui';
import * as R from 'ramda';
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

const addSoftwaresLinesMutationRelationAdd = graphql`
  mutation AddSoftwaresLinesRelationAddMutation(
    $input: StixCoreRelationshipAddInput
  ) {
    stixCoreRelationshipAdd(input: $input) {
      to {
        ...VulnerabilitySoftwares_vulnerability
      }
    }
  }
`;

export const addSoftwaresMutationRelationDelete = graphql`
  mutation AddSoftwaresLinesRelationDeleteMutation(
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

class AddSoftwaresLinesContainer extends Component {
  toggleSoftware(software) {
    const { vulnerabilityId, vulnerabilitySoftwares } = this.props;
    const vulnerabilitySoftwaresIds = map(
      (n) => n.node.id,
      vulnerabilitySoftwares,
    );
    const alreadyAdded = vulnerabilitySoftwaresIds.includes(software.id);
    if (alreadyAdded) {
      const existingSoftware = head(
        filter((n) => n.node.id === software.id, vulnerabilitySoftwares),
      );
      commitMutation({
        mutation: addSoftwaresMutationRelationDelete,
        variables: {
          fromId: existingSoftware.node.id,
          toId: vulnerabilityId,
          relationship_type: 'has',
        },
        updater: (store) => {
          const node = store.get(vulnerabilityId);
          const softwares = node.getLinkedRecord('softwares');
          const edges = softwares.getLinkedRecords('edges');
          const newEdges = filter(
            (n) => n.getLinkedRecord('node').getValue('id')
              !== existingSoftware.node.id,
            edges,
          );
          softwares.setLinkedRecords(newEdges, 'edges');
        },
      });
    } else {
      const input = {
        relationship_type: 'has',
        fromId: software.id,
        toId: vulnerabilityId,
      };
      commitMutation({
        mutation: addSoftwaresLinesMutationRelationAdd,
        variables: { input },
      });
    }
  }

  render() {
    const { classes, data, vulnerabilitySoftwares } = this.props;
    const vulnerabilitySoftwaresIds = map(
      (n) => n.node.id,
      vulnerabilitySoftwares,
    );
    return (
      <List>
        {R.sortBy(
          R.ascend(R.pathOr(['node', 'name'])),
          data.stixCyberObservables.edges,
        ).map((softwareNode) => {
          const software = softwareNode.node;
          const alreadyAdded = vulnerabilitySoftwaresIds.includes(software.id);
          return (
            <ListItem
              key={software.id}
              classes={{ root: classes.menuItem }}
              divider={true}
              button={true}
              onClick={this.toggleSoftware.bind(this, software)}
            >
              <ListItemIcon>
                {alreadyAdded ? (
                  <CheckCircle classes={{ root: classes.icon }} />
                ) : (
                  <HexagonOutline />
                )}
              </ListItemIcon>
              <ListItemText
                primary={`${software.name} ${
                  software.version && software.version.length > 0
                    ? `(${software.version})`
                    : ''
                }`}
                secondary={truncate(software.x_opencti_description, 120)}
              />
            </ListItem>
          );
        })}
      </List>
    );
  }
}

AddSoftwaresLinesContainer.propTypes = {
  vulnerabilityId: PropTypes.string,
  vulnerabilitySoftwares: PropTypes.array,
  data: PropTypes.object,
  classes: PropTypes.object,
};

export const addSoftwaresLinesQuery = graphql`
  query AddSoftwaresLinesQuery($search: String, $count: Int!, $cursor: ID) {
    ...AddSoftwaresLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddSoftawaresLines = createPaginationContainer(
  AddSoftwaresLinesContainer,
  {
    data: graphql`
      fragment AddSoftwaresLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        stixCyberObservables(
          types: ["Software"]
          search: $search
          first: $count
          after: $cursor
        ) @connection(key: "Pagination_stixCyberObservables") {
          edges {
            node {
              id
              x_opencti_description
              ... on Software {
                name
                version
                vendor
              }
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.softwares;
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
    query: addSoftwaresLinesQuery,
  },
);

export default compose(inject18n, withStyles(styles))(AddSoftawaresLines);
