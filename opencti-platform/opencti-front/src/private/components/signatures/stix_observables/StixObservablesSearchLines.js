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
import { Link } from 'react-router-dom';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { truncate } from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import inject18n from '../../../../components/i18n';
import StixObjectTags from '../../common/stix_object/StixObjectTags';

const styles = (theme) => ({
  container: {
    padding: '0 0 20px 0',
  },
  expansionPanel: {
    backgroundColor: theme.palette.background.paper,
  },
  itemIcon: {
    color: theme.palette.primary.main,
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

class StixObservablesContainer extends Component {
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
    if (numberOfTypes === 1) {
      return true;
    }
    return false;
  }

  render() {
    const { t, classes, data } = this.props;
    const stixObservablesNodes = map((n) => n.node, data.stixObservables.edges);
    const byType = groupBy((stixObservable) => stixObservable.entity_type);
    const stixObservables = byType(stixObservablesNodes);
    const stixObservablesTypes = keys(stixObservables);
    return (
      <div className={classes.container}>
        {stixObservablesTypes.map((type) => (
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
            <ExpansionPanelSummary
              expandIcon={<ExpandMore />}
              className={classes.summary}
            >
              <Typography className={classes.heading}>
                {t(`observable_${type}`)}
              </Typography>
              <Typography classes={{ root: classes.secondaryHeading }}>
                {stixObservables[type].length} {t('observable(s)')}
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
                    component={Link}
                    to={`/dashboard/signatures/observables/${stixObservable.id}`}
                  >
                    <ListItemIcon classes={{ root: classes.itemIcon }}>
                      <ItemIcon type={type} />
                    </ListItemIcon>
                    <ListItemText
                      primary={stixObservable.observable_value}
                      secondary={truncate(stixObservable.description, 200)}
                    />
                    <ListItemSecondaryAction>
                      <StixObjectTags
                        tags={stixObservable.tags}
                        variant="inSearch"
                      />
                    </ListItemSecondaryAction>
                  </ListItem>
                ))}
              </List>
            </ExpansionPanelDetails>
          </ExpansionPanel>
        ))}
      </div>
    );
  }
}

StixObservablesContainer.propTypes = {
  reportId: PropTypes.string,
  reportObjectRefs: PropTypes.array,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const stixObservablesSearchLinesQuery = graphql`
  query StixObservablesSearchLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixObservablesOrdering
    $orderMode: OrderingMode
  ) {
    ...StixObservablesSearchLines_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const StixObservablesSearchLines = createPaginationContainer(
  StixObservablesContainer,
  {
    data: graphql`
      fragment StixObservablesSearchLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "StixObservablesOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
        ) {
        stixObservables(
          search: $search
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
              tags {
                edges {
                  node {
                    id
                    tag_type
                    value
                    color
                  }
                  relation {
                    id
                  }
                }
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
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: stixObservablesSearchLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixObservablesSearchLines);
