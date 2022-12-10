import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { map, filter, head, compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { CheckCircle, SpeakerNotesOutlined } from '@mui/icons-material';
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

const addSubNarrativesLinesMutationRelationAdd = graphql`
  mutation AddSubNarrativesLinesRelationAddMutation(
    $input: StixCoreRelationshipAddInput
  ) {
    stixCoreRelationshipAdd(input: $input) {
      to {
        ...NarrativeSubNarratives_narrative
      }
    }
  }
`;

export const addSubNarrativesMutationRelationDelete = graphql`
  mutation AddSubNarrativesLinesRelationDeleteMutation(
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

class AddSubNarrativesLinesContainer extends Component {
  toggleSubNarrative(subNarrative) {
    const { narrativeId, narrativeSubNarratives } = this.props;
    const narrativeSubNarrativesIds = map(
      (n) => n.node.id,
      narrativeSubNarratives,
    );
    const alreadyAdded = narrativeSubNarrativesIds.includes(subNarrative.id);

    if (alreadyAdded) {
      const existingSubNarrative = head(
        filter((n) => n.node.id === subNarrative.id, narrativeSubNarratives),
      );
      commitMutation({
        mutation: addSubNarrativesMutationRelationDelete,
        variables: {
          fromId: existingSubNarrative.node.id,
          toId: narrativeId,
          relationship_type: 'subnarrative-of',
        },
        updater: (store) => {
          const node = store.get(this.props.narrativeId);
          const subNarratives = node.getLinkedRecord('subNarratives');
          const edges = subNarratives.getLinkedRecords('edges');
          const newEdges = filter(
            (n) => n.getLinkedRecord('node').getValue('id')
              !== existingSubNarrative.node.id,
            edges,
          );
          subNarratives.setLinkedRecords(newEdges, 'edges');
        },
      });
    } else {
      const input = {
        relationship_type: 'subnarrative-of',
        fromId: subNarrative.id,
        toId: narrativeId,
      };
      commitMutation({
        mutation: addSubNarrativesLinesMutationRelationAdd,
        variables: { input },
      });
    }
  }

  render() {
    const { classes, data, narrativeSubNarratives } = this.props;
    const narrativeSubNarrativesIds = map(
      (n) => n.node.id,
      narrativeSubNarratives,
    );
    return (
      <List>
        {data.narratives.edges.map((narrativeNode) => {
          const narrative = narrativeNode.node;
          const alreadyAdded = narrativeSubNarrativesIds.includes(narrative.id);
          return (
            <ListItem
              key={narrative.id}
              classes={{ root: classes.menuItem }}
              divider={true}
              button={true}
              onClick={this.toggleSubNarrative.bind(this, narrative)}
            >
              <ListItemIcon>
                {alreadyAdded ? (
                  <CheckCircle classes={{ root: classes.icon }} />
                ) : (
                  <SpeakerNotesOutlined />
                )}
              </ListItemIcon>
              <ListItemText
                primary={narrative.name}
                secondary={truncate(narrative.description, 120)}
              />
            </ListItem>
          );
        })}
      </List>
    );
  }
}

AddSubNarrativesLinesContainer.propTypes = {
  narrativeId: PropTypes.string,
  narrativeSubNarratives: PropTypes.array,
  data: PropTypes.object,
  classes: PropTypes.object,
};

export const addSubNarrativesLinesQuery = graphql`
  query AddSubNarrativesLinesQuery($search: String, $count: Int!, $cursor: ID) {
    ...AddSubNarrativesLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddSubNarrativesLines = createPaginationContainer(
  AddSubNarrativesLinesContainer,
  {
    data: graphql`
      fragment AddSubNarrativesLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        narratives(search: $search, first: $count, after: $cursor)
          @connection(key: "Pagination_narratives") {
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
      return props.data && props.data.subNarratives;
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
    query: addSubNarrativesLinesQuery,
  },
);

export default compose(inject18n, withStyles(styles))(AddSubNarrativesLines);
