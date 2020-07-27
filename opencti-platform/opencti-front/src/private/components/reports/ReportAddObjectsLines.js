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
import { reportRefPopoverDeletionMutation } from './ReportObjectPopover';
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
  mutation ReportAddObjectsLinesRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
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

class ReportAddObjectsLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { expandedPanels: {}, addedStixCoreObjects: [] };
  }

  toggleStixCore(stixCore) {
    const {
      reportId,
      paginationOptions,
      knowledgeGraph,
      reportObjects,
    } = this.props;
    const { addedStixCoreObjects } = this.state;
    const reportObjectsIds = map((n) => n.node.id, reportObjects);
    const alreadyAdded = addedStixCoreObjects.includes(stixCore.id)
      || reportObjectsIds.includes(stixCore.id);

    if (alreadyAdded) {
      if (knowledgeGraph) {
        commitMutation({
          mutation: reportKnowledgeGraphtMutationRelationDelete,
          variables: {
            id: reportId,
            toId: stixCore.id,
            relationship_type: 'object_refs',
          },
          onCompleted: () => {
            this.setState({
              addedStixCoreObjects: filter(
                (n) => n !== stixCore.id,
                this.state.addedStixCoreObjects,
              ),
            });
          },
        });
      } else {
        commitMutation({
          mutation: reportRefPopoverDeletionMutation,
          variables: {
            id: reportId,
            toId: stixCore.id,
            relationship_type: 'object_refs',
          },
          updater: (store) => {
            const conn = ConnectionHandler.getConnection(
              store.get(reportId),
              'Pagination_objects',
              this.props.paginationOptions,
            );
            ConnectionHandler.deleteNode(conn, stixCore.id);
          },
          onCompleted: () => {
            this.setState({
              addedStixCoreObjects: filter(
                (n) => n !== stixCore.id,
                this.state.addedStixCoreObjects,
              ),
            });
          },
        });
      }
    } else {
      const input = {
        fromRole: 'knowledge_aggregation',
        toId: stixCore.id,
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
              addedStixCoreObjects: append(
                stixCore.id,
                this.state.addedStixCoreObjects,
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
              'Pagination_objects',
              paginationOptions,
            );
            ConnectionHandler.insertEdgeBefore(conn, newEdge);
          },
          onCompleted: () => {
            this.setState({
              addedStixCoreObjects: append(
                stixCore.id,
                this.state.addedStixCoreObjects,
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
      t, classes, data, reportObjects,
    } = this.props;
    const { addedStixCoreObjects } = this.state;
    const stixCoreObjectsNodes = map((n) => n.node, data.stixCoreObjects.edges);
    const byType = groupBy((stixCoreObject) => stixCoreObject.entity_type);
    const stixCoreObjects = byType(stixCoreObjectsNodes);
    const stixCoreObjectsTypes = keys(stixCoreObjects);
    const reportObjectsIds = map((n) => n.node.id, reportObjects);
    return (
      <div className={classes.container}>
        {stixCoreObjectsTypes.length > 0 ? (
          stixCoreObjectsTypes.map((type) => (
            <ExpansionPanel
              key={type}
              expanded={this.isExpanded(
                type,
                stixCoreObjects[type].length,
                stixCoreObjectsTypes.length,
              )}
              onChange={this.handleChangePanel.bind(this, type)}
              classes={{ root: classes.expansionPanel }}
            >
              <ExpansionPanelSummary expandIcon={<ExpandMore />}>
                <Typography className={classes.heading}>
                  {t(`entity_${type}`)}
                </Typography>
                <Typography className={classes.secondaryHeading}>
                  {stixCoreObjects[type].length} {t('entitie(s)')}
                </Typography>
              </ExpansionPanelSummary>
              <ExpansionPanelDetails
                classes={{ root: classes.expansionPanelContent }}
              >
                <List classes={{ root: classes.list }}>
                  {stixCoreObjects[type].map((stixCoreObject) => {
                    const alreadyAdded = addedStixCoreObjects.includes(stixCoreObject.id)
                      || reportObjectsIds.includes(stixCoreObject.id);
                    return (
                      <Tooltip
                        classes={{ tooltip: classes.tooltip }}
                        title={<Markdown source={stixCoreObject.description} />}
                        key={stixCoreObject.id}
                      >
                        <ListItem
                          classes={{ root: classes.menuItem }}
                          divider={true}
                          button={true}
                          onClick={this.toggleStixCore.bind(
                            this,
                            stixCoreObject,
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
                            primary={stixCoreObject.name}
                            secondary={
                              <Markdown
                                className="markdown"
                                source={truncate(
                                  stixCoreObject.description,
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

ReportAddObjectsLinesContainer.propTypes = {
  reportId: PropTypes.string,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  paginationOptions: PropTypes.object,
  knowledgeGraph: PropTypes.bool,
  reportObjects: PropTypes.array,
};

export const reportAddObjectsLinesQuery = graphql`
  query ReportAddObjectsLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
  ) {
    ...ReportAddObjectsLines_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const ReportAddObjectsLines = createPaginationContainer(
  ReportAddObjectsLinesContainer,
  {
    data: graphql`
      fragment ReportAddObjectsLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: {
            type: "StixCoreObjectsOrdering"
            defaultValue: "created_at"
          }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
        ) {
        stixCoreObjects(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_stixCoreObjects") {
          edges {
            node {
              id
              entity_type
              ... on AttackPattern {
                name
                description
              }
              ... on Campaign {
                name
                description
              }
              ... on CourseOfAction {
                name
                description
              }
              ... on Individual {
                name
                description
              }
              ... on Organization {
                name
                description
              }
              ... on Sector {
                name
                description
              }
              ... on Indicator {
                name
                description
              }
              ... on Infrastructure {
                name
                description
              }
              ... on IntrusionSet {
                name
                description
              }
              ... on Position {
                name
                description
              }
              ... on City {
                name
                description
              }
              ... on Country {
                name
                description
              }
              ... on Region {
                name
                description
              }
              ... on Malware {
                name
                description
              }
              ... on ThreatActor {
                name
                description
              }
              ... on Tool {
                name
                description
              }
              ... on Vulnerability {
                name
                description
              }
              ... on XOpenctiIncident {
                name
                description
              }
              ... on StixCyberObservable {
                observable_value
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
      return props.data && props.data.stixCoreObjects;
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
    query: reportAddObjectsLinesQuery,
  },
);

export default compose(inject18n, withStyles(styles))(ReportAddObjectsLines);
