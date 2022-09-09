import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { map, assoc, compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { CheckCircle } from '@mui/icons-material';
import { ConnectionHandler } from 'relay-runtime';
import { commitMutation } from '../../../../relay/environment';
import ItemIcon from '../../../../components/ItemIcon';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  container: {
    padding: '20px 0 20px 0',
  },
  heading: {
    fontSize: theme.typography.pxToRem(15),
    flexBasis: '33.33%',
    flexShrink: 0,
  },
  secondaryHeading: {
    fontSize: theme.typography.pxToRem(15),
    color: theme.palette.text.secondary,
  },
  expansionPanelContent: {
    padding: 0,
  },
  list: {
    width: '100%',
  },
  listItem: {
    width: '100M',
  },
  icon: {
    color: theme.palette.primary.main,
  },
});

export const stixCyberObservableMutationRelationAdd = graphql`
  mutation StixCyberObservableAddIndicatorsLinesRelationAddMutation(
    $input: StixCoreRelationshipAddInput!
  ) {
    stixCoreRelationshipAdd(input: $input) {
      id
      to {
        ...StixCyberObservableIndicators_stixCyberObservable
      }
    }
  }
`;

export const stixCyberObservableMutationRelationDelete = graphql`
  mutation StixCyberObservableAddIndicatorsLinesRelationDeleteMutation(
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

class StixCyberObservableAddIndicatorsLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { expandedPanels: {} };
  }

  toggleIndicator(indicator) {
    const { stixCyberObservableId, stixCyberObservableIndicators } = this.props;
    const stixCyberObservableIndicatorsIds = map(
      (n) => n.node.id,
      stixCyberObservableIndicators,
    );
    const alreadyAdded = stixCyberObservableIndicatorsIds.includes(
      indicator.id,
    );
    if (alreadyAdded) {
      commitMutation({
        mutation: stixCyberObservableMutationRelationDelete,
        variables: {
          fromId: indicator.id,
          toId: stixCyberObservableId,
          relationship_type: 'based-on',
        },
        updater: (store) => {
          const conn = ConnectionHandler.getConnection(
            store.get(stixCyberObservableId),
            'Pagination_indicators',
          );
          ConnectionHandler.deleteNode(conn, indicator.id);
        },
      });
    } else {
      const input = {
        fromId: indicator.id,
        toId: stixCyberObservableId,
        relationship_type: 'based-on',
      };
      commitMutation({
        mutation: stixCyberObservableMutationRelationAdd,
        variables: { input },
      });
    }
  }

  handleChangePanel(panelKey, event, expanded) {
    this.setState({
      expandedPanels: assoc(panelKey, expanded, this.state.expandedPanels),
    });
  }

  isExpanded(type, numberOfEntities, numberOfTypes) {
    if (this.state.expandedPanels[type] !== undefined) {
      return this.state.expandedPanels[type];
    }
    if (numberOfEntities === 1) {
      return true;
    }
    return numberOfTypes === 1;
  }

  render() {
    const { t, classes, data, stixCyberObservableIndicators } = this.props;
    const stixCyberObservableIndicatorsIds = map(
      (n) => n.node.id,
      stixCyberObservableIndicators,
    );
    const indicatorsNodes = map((n) => n.node, data.indicators.edges);
    return (
      <div className={classes.container}>
        {indicatorsNodes.length > 0 ? (
          <List classes={{ root: classes.list }}>
            {indicatorsNodes.map((indicator) => {
              const alreadyAdded = stixCyberObservableIndicatorsIds.includes(
                indicator.id,
              );
              return (
                <ListItem
                  key={indicator.id}
                  classes={{ root: classes.menuItem }}
                  divider={true}
                  button={true}
                  onClick={this.toggleIndicator.bind(this, indicator)}
                >
                  <ListItemIcon>
                    {alreadyAdded ? (
                      <CheckCircle classes={{ root: classes.icon }} />
                    ) : (
                      <ItemIcon type="Indicator" />
                    )}
                  </ListItemIcon>
                  <ListItemText
                    primary={indicator.name}
                    secondary={indicator.description || indicator.pattern}
                  />
                </ListItem>
              );
            })}
          </List>
        ) : (
          <div style={{ paddingLeft: 20 }}>
            {t('No entities were found for this search.')}
          </div>
        )}
      </div>
    );
  }
}

StixCyberObservableAddIndicatorsLinesContainer.propTypes = {
  stixCyberObservableId: PropTypes.string,
  stixCyberObservableIndicators: PropTypes.array,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const stixCyberObservableAddIndicatorsLinesQuery = graphql`
  query StixCyberObservableAddIndicatorsLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: IndicatorsOrdering
    $orderMode: OrderingMode
  ) {
    ...StixCyberObservableAddIndicatorsLines_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const StixCyberObservableAddIndicatorsLines = createPaginationContainer(
  StixCyberObservableAddIndicatorsLinesContainer,
  {
    data: graphql`
      fragment StixCyberObservableAddIndicatorsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "IndicatorsOrdering", defaultValue: created_at }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        indicators(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_indicators") {
          edges {
            node {
              id
              entity_type
              name
              pattern
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
      return props.data && props.data.indicators;
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
    query: stixCyberObservableAddIndicatorsLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixCyberObservableAddIndicatorsLines);
