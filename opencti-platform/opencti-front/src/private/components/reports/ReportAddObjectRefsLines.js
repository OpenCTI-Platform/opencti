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
import Tooltip from '@material-ui/core/Tooltip';
import Markdown from 'react-markdown';
import { commitMutation } from '../../../relay/environment';
import { truncate } from '../../../utils/String';
import ItemIcon from '../../../components/ItemIcon';
import inject18n from '../../../components/i18n';
import { reportRefPopoverDeletionMutation } from './ReportRefPopover';
import {
  reportKnowledgeGraphtMutationRelationAdd,
  reportKnowledgeGraphtMutationRelationDelete,
} from './ReportKnowledgeGraph';

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
  tooltip: {
    maxWidth: '80%',
    lineHeight: 2,
    padding: 10,
    backgroundColor: '#323232',
  },
});

export const reportMutationRelationAdd = graphql`
  mutation ReportAddObjectRefsLinesRelationAddMutation(
    $id: ID!
    $input: RelationAddInput!
  ) {
    reportEdit(id: $id) {
      relationAdd(input: $input) {
        id
        to {
          ...ReportEntityLine_node
        }
      }
    }
  }
`;

class ReportAddObjectRefsLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { expandedPanels: {}, addedStixDomainEntities: [] };
  }

  toggleStixDomain(stixDomain) {
    const {
      reportId,
      paginationOptions,
      knowledgeGraph,
      reportObjectRefs,
    } = this.props;
    const { addedStixDomainEntities } = this.state;
    const reportObjectRefsIds = map((n) => n.node.id, reportObjectRefs);
    const alreadyAdded = addedStixDomainEntities.includes(stixDomain.id)
      || reportObjectRefsIds.includes(stixDomain.id);

    if (alreadyAdded) {
      if (knowledgeGraph) {
        commitMutation({
          mutation: reportKnowledgeGraphtMutationRelationDelete,
          variables: {
            id: reportId,
            toId: stixDomain.id,
            relationType: 'object_refs',
          },
          onCompleted: () => {
            this.setState({
              addedStixDomainEntities: filter(
                (n) => n !== stixDomain.id,
                this.state.addedStixDomainEntities,
              ),
            });
          },
        });
      } else {
        commitMutation({
          mutation: reportRefPopoverDeletionMutation,
          variables: {
            id: reportId,
            toId: stixDomain.id,
            relationType: 'object_refs',
          },
          updater: (store) => {
            const conn = ConnectionHandler.getConnection(
              store.get(reportId),
              'Pagination_objectRefs',
              this.props.paginationOptions,
            );
            ConnectionHandler.deleteNode(conn, stixDomain.id);
          },
          onCompleted: () => {
            this.setState({
              addedStixDomainEntities: filter(
                (n) => n !== stixDomain.id,
                this.state.addedStixDomainEntities,
              ),
            });
          },
        });
      }
    } else {
      const input = {
        fromRole: 'knowledge_aggregation',
        toId: stixDomain.id,
        toRole: 'so',
        through: 'object_refs',
      };
      if (knowledgeGraph) {
        commitMutation({
          mutation: reportKnowledgeGraphtMutationRelationAdd,
          variables: {
            id: reportId,
            input,
          },
          onCompleted: () => {
            this.setState({
              addedStixDomainEntities: append(
                stixDomain.id,
                this.state.addedStixDomainEntities,
              ),
            });
          },
        });
      } else {
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
              'Pagination_objectRefs',
              paginationOptions,
            );
            ConnectionHandler.insertEdgeBefore(conn, newEdge);
          },
          onCompleted: () => {
            this.setState({
              addedStixDomainEntities: append(
                stixDomain.id,
                this.state.addedStixDomainEntities,
              ),
            });
          },
        });
      }
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
    const {
      t, classes, data, reportObjectRefs,
    } = this.props;
    const { addedStixDomainEntities } = this.state;
    const stixDomainEntitiesNodes = map(
      (n) => n.node,
      data.stixDomainEntities.edges,
    );
    const byType = groupBy((stixDomainEntity) => stixDomainEntity.entity_type);
    const stixDomainEntities = byType(stixDomainEntitiesNodes);
    const stixDomainEntitiesTypes = keys(stixDomainEntities);
    const reportObjectRefsIds = map((n) => n.node.id, reportObjectRefs);
    return (
      <div className={classes.container}>
        {stixDomainEntitiesTypes.length > 0 ? (
          stixDomainEntitiesTypes.map((type) => (
            <ExpansionPanel
              key={type}
              expanded={this.isExpanded(
                type,
                stixDomainEntities[type].length,
                stixDomainEntitiesTypes.length,
              )}
              onChange={this.handleChangePanel.bind(this, type)}
              classes={{ root: classes.expansionPanel }}
            >
              <ExpansionPanelSummary expandIcon={<ExpandMore />}>
                <Typography className={classes.heading}>
                  {t(`entity_${type}`)}
                </Typography>
                <Typography className={classes.secondaryHeading}>
                  {stixDomainEntities[type].length} {t('entitie(s)')}
                </Typography>
              </ExpansionPanelSummary>
              <ExpansionPanelDetails
                classes={{ root: classes.expansionPanelContent }}
              >
                <List classes={{ root: classes.list }}>
                  {stixDomainEntities[type].map((stixDomainEntity) => {
                    const alreadyAdded = addedStixDomainEntities.includes(stixDomainEntity.id)
                      || reportObjectRefsIds.includes(stixDomainEntity.id);
                    return (
                      <Tooltip
                        classes={{ tooltip: classes.tooltip }}
                        title={
                          <Markdown source={stixDomainEntity.description} />
                        }
                        key={stixDomainEntity.id}
                      >
                        <ListItem
                          classes={{ root: classes.menuItem }}
                          divider={true}
                          button={true}
                          onClick={this.toggleStixDomain.bind(
                            this,
                            stixDomainEntity,
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
                            primary={stixDomainEntity.name}
                            secondary={
                              <Markdown
                                className="markdown"
                                source={truncate(
                                  stixDomainEntity.description,
                                  200,
                                )}
                              />
                            }
                          />
                        </ListItem>
                      </Tooltip>
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

ReportAddObjectRefsLinesContainer.propTypes = {
  reportId: PropTypes.string,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  paginationOptions: PropTypes.object,
  knowledgeGraph: PropTypes.bool,
  reportObjectRefs: PropTypes.array,
};

export const reportAddObjectRefsLinesQuery = graphql`
  query ReportAddObjectRefsLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixDomainEntitiesOrdering
    $orderMode: OrderingMode
  ) {
    ...ReportAddObjectRefsLines_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const ReportAddObjectRefsLines = createPaginationContainer(
  ReportAddObjectRefsLinesContainer,
  {
    data: graphql`
      fragment ReportAddObjectRefsLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }

          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "StixDomainEntitiesOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
        ) {
        stixDomainEntities(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_stixDomainEntities") {
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
      return props.data && props.data.stixDomainEntities;
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
    query: reportAddObjectRefsLinesQuery,
  },
);

export default compose(inject18n, withStyles(styles))(ReportAddObjectRefsLines);
