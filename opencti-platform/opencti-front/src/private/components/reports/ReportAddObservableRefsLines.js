import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import {
  map, filter, keys, groupBy, assoc, compose, append,
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
import { ExpandMore, CheckCircle } from '@material-ui/icons';
import { ConnectionHandler } from 'relay-runtime';
import { commitMutation } from '../../../relay/environment';
import ItemIcon from '../../../components/ItemIcon';
import inject18n from '../../../components/i18n';
import { reportRefPopoverDeletionMutation } from './ReportRefPopover';

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

export const reportMutationRelationAdd = graphql`
  mutation ReportAddObservableRefsLinesRelationAddMutation(
    $id: ID!
    $input: RelationAddInput!
  ) {
    reportEdit(id: $id) {
      relationAdd(input: $input) {
        id
        to {
          ...ReportObservableLine_node
        }
      }
    }
  }
`;

class ReportAddObservableRefsLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { expandedPanels: {}, addedObservables: [] };
  }

  toggleStixObservable(stixObservable) {
    const { reportId, paginationOptions } = this.props;
    const alreadyAdded = this.state.addedObservables.includes(
      stixObservable.id,
    );

    if (alreadyAdded) {
      commitMutation({
        mutation: reportRefPopoverDeletionMutation,
        variables: {
          id: reportId,
          toId: stixObservable.id,
          relationType: 'observable_refs',
        },
        updater: (store) => {
          const conn = ConnectionHandler.getConnection(
            store.get(reportId),
            'Pagination_observableRefs',
            paginationOptions,
          );
          ConnectionHandler.deleteNode(conn, stixObservable.id);
        },
        onCompleted: () => {
          this.setState({
            addedObservables: filter(
              (n) => n !== stixObservable.id,
              this.state.addedObservables,
            ),
          });
        },
      });
    } else {
      const input = {
        fromRole: 'observables_aggregation',
        toId: stixObservable.id,
        toRole: 'soo',
        through: 'observable_refs',
      };
      commitMutation({
        mutation: reportMutationRelationAdd,
        variables: {
          id: reportId,
          input,
        },
        updater: (store) => {
          const payload = store
            .getRootField('reportEdit')
            .getLinkedRecord('relationAdd', { input })
            .getLinkedRecord('to');
          const newEdge = payload.setLinkedRecord(payload, 'node');
          const conn = ConnectionHandler.getConnection(
            store.get(reportId),
            'Pagination_observableRefs',
            this.props.paginationOptions,
          );
          ConnectionHandler.insertEdgeBefore(conn, newEdge);
        },
        onCompleted: () => {
          this.setState({
            addedObservables: append(
              stixObservable.id,
              this.state.addedObservables,
            ),
          });
        },
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
    const { t, classes, data } = this.props;
    const { addedObservables } = this.state;
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
                  {stixObservables[type].map((stixObservable) => {
                    const alreadyAdded = addedObservables.includes(
                      stixObservable.id,
                    );
                    return (
                      <ListItem
                        key={stixObservable.id}
                        classes={{ root: classes.menuItem }}
                        divider={true}
                        button={true}
                        onClick={this.toggleStixObservable.bind(
                          this,
                          stixObservable,
                        )}
                      >
                        <ListItemIcon>
                          {alreadyAdded ? (
                            <CheckCircle classes={{ root: classes.icon }} />
                          ) : (
                            <ItemIcon type={type} />
                          )}
                        </ListItemIcon>
                        <ListItemText
                          primary={stixObservable.observable_value}
                        />
                      </ListItem>
                    );
                  })}
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

ReportAddObservableRefsLinesContainer.propTypes = {
  reportId: PropTypes.string,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  paginationOptions: PropTypes.object,
};

export const reportAddObservableRefsLinesQuery = graphql`
  query ReportAddObservableRefsLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixObservablesOrdering
    $orderMode: OrderingMode
  ) {
    ...ReportAddObservableRefsLines_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const ReportAddObservableRefsLines = createPaginationContainer(
  ReportAddObservableRefsLinesContainer,
  {
    data: graphql`
      fragment ReportAddObservableRefsLines_data on Query
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
    query: reportAddObservableRefsLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(ReportAddObservableRefsLines);
