import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import {
  map, keys, groupBy, assoc, compose,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import ExpansionPanel from '@material-ui/core/ExpansionPanel';
import ExpansionPanelDetails from '@material-ui/core/ExpansionPanelDetails';
import ExpansionPanelSummary from '@material-ui/core/ExpansionPanelSummary';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Typography from '@material-ui/core/Typography';
import { ExpandMore } from '@material-ui/icons';
import { truncate } from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  container: {
    padding: '20px 0 20px 0',
  },
  expansionPanel: {
    backgroundColor: '#193E45',
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

class StixObservableRelationCreationFromEntityLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { expandedPanels: {} };
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
    const {
      t, classes, data, handleSelect,
    } = this.props;
    const stixObservablesNodes = map((n) => n.node, data.stixObservables.edges);
    const byType = groupBy((stixObservable) => stixObservable.entity_type);
    const stixObservables = byType(stixObservablesNodes);
    const stixObservablesTypes = keys(stixObservables);

    return (
      <div className={classes.container}>
        {stixObservablesTypes.length > 0 ? (
          stixObservablesTypes.map((type) => (
            <ExpansionPanel
              key={type}
              expanded={this.isExpanded(
                type,
                stixObservables[type].length,
                stixObservablesTypes.length,
              )}
              onChange={this.handleChangePanel.bind(this, type)}
              classes={{ root: classes.expansionPanel }}
            >
              <ExpansionPanelSummary expandIcon={<ExpandMore />}>
                <Typography className={classes.heading}>
                  {t(`observable_${type}`)}
                </Typography>
                <Typography className={classes.secondaryHeading}>
                  {stixObservables[type].length} {t('entitie(s)')}
                </Typography>
              </ExpansionPanelSummary>
              <ExpansionPanelDetails
                classes={{ root: classes.expansionPanelContent }}
              >
                <List classes={{ root: classes.list }}>
                  {stixObservables[type].map((stixObservable) => (
                    <ListItem
                      key={stixObservable.id}
                      classes={{ root: classes.menuItem }}
                      divider={true}
                      button={true}
                      onClick={handleSelect.bind(this, stixObservable)}
                    >
                      <ListItemIcon>
                        <ItemIcon type={type} />
                      </ListItemIcon>
                      <ListItemText
                        primary={truncate(stixObservable.observable_value, 100)}
                      />
                    </ListItem>
                  ))}
                </List>
              </ExpansionPanelDetails>
            </ExpansionPanel>
          ))
        ) : (
          <div style={{ paddingLeft: 20 }}>
            {t('No entities were found for this search.')}
          </div>
        )}
      </div>
    );
  }
}

StixObservableRelationCreationFromEntityLinesContainer.propTypes = {
  handleSelect: PropTypes.func,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const stixObservableRelationCreationFromEntityLinesQuery = graphql`
  query StixObservableRelationCreationFromEntityLinesQuery(
    $search: String
    $types: [String]
    $count: Int!
    $cursor: ID
    $orderBy: StixObservablesOrdering
    $orderMode: OrderingMode
  ) {
    ...StixObservableRelationCreationFromEntityLines_data
      @arguments(
        search: $search
        types: $types
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const StixObservableRelationCreationFromEntityLines = createPaginationContainer(
  StixObservableRelationCreationFromEntityLinesContainer,
  {
    data: graphql`
      fragment StixObservableRelationCreationFromEntityLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          types: { type: "[String]" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "StixObservablesOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
        ) {
        stixObservables(
          search: $search
          types: $types
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_stixObservables") {
          edges {
            node {
              id
              entity_type
              observable_value
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.stixObservables;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        search: fragmentVariables.search,
        types: fragmentVariables.types,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: stixObservableRelationCreationFromEntityLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixObservableRelationCreationFromEntityLines);
