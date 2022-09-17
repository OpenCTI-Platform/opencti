import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import {
  map,
  filter,
  keys,
  groupBy,
  assoc,
  compose,
  append,
  pipe,
} from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Accordion from '@mui/material/Accordion';
import AccordionDetails from '@mui/material/AccordionDetails';
import AccordionSummary from '@mui/material/AccordionSummary';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import { ExpandMore, CheckCircle } from '@mui/icons-material';
import { ConnectionHandler } from 'relay-runtime';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import { commitMutation } from '../../../../relay/environment';
import { truncate } from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import inject18n from '../../../../components/i18n';
import {
  reportKnowledgeGraphtMutationRelationAddMutation,
  reportKnowledgeGraphMutationRelationDeleteMutation,
} from '../../analysis/reports/ReportKnowledgeGraphQuery';

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
    width: '100%',
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

export const containerAddStixCoreObjectsLinesRelationAddMutation = graphql`
  mutation ContainerAddStixCoreObjectsLinesRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    containerEdit(id: $id) {
      relationAdd(input: $input) {
        id
        to {
          ... on StixDomainObject {
            ...ContainerStixDomainObjectLine_node
          }
          ... on StixCyberObservable {
            ...ContainerStixCyberObservableLine_node
          }
          ... on StixFile {
            observableName: name
          }
        }
      }
    }
  }
`;

export const containerAddStixCoreObjectsLinesRelationDeleteMutation = graphql`
  mutation ContainerAddStixCoreObjectsLinesRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    containerEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        id
      }
    }
  }
`;

class ContainerAddStixCoreObjectsLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { expandedPanels: {}, addedStixCoreObjects: [] };
  }

  getContainerStixCoreObjectsIds() {
    const { containerStixCoreObjects } = this.props;
    return map((n) => n.node.id, containerStixCoreObjects || []);
  }

  toggleStixCoreObject(stixCoreObject) {
    const { containerId, paginationOptions, knowledgeGraph, onAdd, onDelete } = this.props;
    const { addedStixCoreObjects } = this.state;
    const containerStixCoreObjectsIds = this.getContainerStixCoreObjectsIds();
    const alreadyAdded = addedStixCoreObjects.includes(stixCoreObject.id)
      || containerStixCoreObjectsIds.includes(stixCoreObject.id);
    if (alreadyAdded) {
      if (knowledgeGraph) {
        commitMutation({
          mutation: reportKnowledgeGraphMutationRelationDeleteMutation,
          variables: {
            id: containerId,
            toId: stixCoreObject.id,
            relationship_type: 'object',
          },
          onCompleted: () => {
            this.setState({
              addedStixCoreObjects: filter(
                (n) => n !== stixCoreObject.id,
                this.state.addedStixCoreObjects,
              ),
            });
            if (typeof onDelete === 'function') {
              onDelete(stixCoreObject);
            }
          },
        });
      } else {
        commitMutation({
          mutation: containerAddStixCoreObjectsLinesRelationDeleteMutation,
          variables: {
            id: containerId,
            toId: stixCoreObject.id,
            relationship_type: 'object',
          },
          updater: (store) => {
            const conn = ConnectionHandler.getConnection(
              store.get(containerId),
              'Pagination_objects',
              this.props.paginationOptions,
            );
            ConnectionHandler.deleteNode(conn, stixCoreObject.id);
          },
          onCompleted: () => {
            this.setState({
              addedStixCoreObjects: filter(
                (n) => n !== stixCoreObject.id,
                this.state.addedStixCoreObjects,
              ),
            });
          },
        });
      }
    } else {
      const input = {
        toId: stixCoreObject.id,
        relationship_type: 'object',
      };
      if (knowledgeGraph) {
        commitMutation({
          mutation: reportKnowledgeGraphtMutationRelationAddMutation,
          variables: {
            id: containerId,
            input,
          },
          onCompleted: () => {
            this.setState({
              addedStixCoreObjects: append(
                stixCoreObject.id,
                this.state.addedStixCoreObjects,
              ),
            });
            if (typeof onAdd === 'function') {
              onAdd(stixCoreObject);
            }
          },
        });
      } else {
        commitMutation({
          mutation: containerAddStixCoreObjectsLinesRelationAddMutation,
          variables: {
            id: containerId,
            input,
          },
          updater: (store) => {
            const payload = store
              .getRootField('containerEdit')
              .getLinkedRecord('relationAdd', { input })
              .getLinkedRecord('to');
            const newEdge = payload.setLinkedRecord(payload, 'node');
            const conn = ConnectionHandler.getConnection(
              store.get(containerId),
              'Pagination_objects',
              paginationOptions,
            );
            ConnectionHandler.insertEdgeBefore(conn, newEdge);
          },
          onCompleted: () => {
            this.setState({
              addedStixCoreObjects: append(
                stixCoreObject.id,
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
    const { t, classes, data, fd } = this.props;
    const { addedStixCoreObjects } = this.state;
    const stixCoreObjectsNodes = pipe(
      map((n) => n.node),
      filter((n) => n.entity_type !== 'Note' && n.entity_type !== 'Opinion'),
    )(data.stixCoreObjects.edges);
    const byType = groupBy((stixCoreObject) => stixCoreObject.entity_type);
    const stixCoreObjects = byType(stixCoreObjectsNodes);
    const stixCoreObjectsTypes = keys(stixCoreObjects);
    const containerStixCoreObjectsIds = this.getContainerStixCoreObjectsIds();
    return (
      <div className={classes.container}>
        {stixCoreObjectsTypes.length > 0 ? (
          stixCoreObjectsTypes.map((type) => (
            <Accordion
              key={type}
              expanded={this.isExpanded(
                type,
                stixCoreObjects[type].length,
                stixCoreObjectsTypes.length,
              )}
              onChange={this.handleChangePanel.bind(this, type)}
              elevation={3}
            >
              <AccordionSummary expandIcon={<ExpandMore />}>
                <Typography className={classes.heading}>
                  {t(`entity_${type}`)}
                </Typography>
                <Typography className={classes.secondaryHeading}>
                  {stixCoreObjects[type].length} {t('entitie(s)')}
                </Typography>
              </AccordionSummary>
              <AccordionDetails
                classes={{ root: classes.expansionPanelContent }}
              >
                <List classes={{ root: classes.list }}>
                  {stixCoreObjects[type].map((stixCoreObject) => {
                    const alreadyAdded = addedStixCoreObjects.includes(stixCoreObject.id)
                      || containerStixCoreObjectsIds.includes(stixCoreObject.id);
                    return (
                      <ListItem
                        key={stixCoreObject.id}
                        classes={{ root: classes.menuItem }}
                        divider={true}
                        button={true}
                        onClick={this.toggleStixCoreObject.bind(
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
                          primary={`${
                            stixCoreObject.x_mitre_id
                              ? `[${stixCoreObject.x_mitre_id}] `
                              : ''
                          }${truncate(
                            stixCoreObject.name
                              || stixCoreObject.observable_value
                              || stixCoreObject.attribute_abstract
                              || stixCoreObject.content
                              || stixCoreObject.opinion
                              || `${fd(stixCoreObject.first_observed)} - ${fd(
                                stixCoreObject.last_observed,
                              )}`,
                            60,
                          )}`}
                          secondary={
                            <Markdown
                              remarkPlugins={[remarkGfm, remarkParse]}
                              parserOptions={{ commonmark: true }}
                              className="markdown"
                            >
                              {truncate(
                                stixCoreObject.description
                                  || fd(stixCoreObject.created_at),
                                200,
                              )}
                            </Markdown>
                          }
                        />
                      </ListItem>
                    );
                  })}
                </List>
              </AccordionDetails>
            </Accordion>
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

ContainerAddStixCoreObjectsLinesContainer.propTypes = {
  containerId: PropTypes.string,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  paginationOptions: PropTypes.object,
  knowledgeGraph: PropTypes.bool,
  containerStixCoreObjects: PropTypes.array,
  onAdd: PropTypes.func,
  onDelete: PropTypes.func,
};

export const containerAddStixCoreObjectsLinesQuery = graphql`
  query ContainerAddStixCoreObjectsLinesQuery(
    $types: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
  ) {
    ...ContainerAddStixCoreObjectsLines_data
      @arguments(
        types: $types
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const ContainerAddStixCoreObjectsLines = createPaginationContainer(
  ContainerAddStixCoreObjectsLinesContainer,
  {
    data: graphql`
      fragment ContainerAddStixCoreObjectsLines_data on Query
      @argumentDefinitions(
        types: { type: "[String]" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "StixCoreObjectsOrdering", defaultValue: created_at }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        stixCoreObjects(
          types: $types
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
              parent_types
              created_at
              createdBy {
                ... on Identity {
                  id
                  name
                  entity_type
                }
              }
              objectMarking {
                edges {
                  node {
                    id
                    definition
                  }
                }
              }
              ... on AttackPattern {
                name
                description
                x_mitre_id
              }
              ... on Campaign {
                name
                description
                first_seen
                last_seen
              }
              ... on Note {
                attribute_abstract
              }
              ... on ObservedData {
                name
                first_observed
                last_observed
              }
              ... on Opinion {
                opinion
              }
              ... on Report {
                name
                description
                published
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
              ... on System {
                name
                description
              }
              ... on Indicator {
                name
                description
                valid_from
              }
              ... on Infrastructure {
                name
                description
              }
              ... on IntrusionSet {
                name
                description
                first_seen
                last_seen
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
                first_seen
                last_seen
              }
              ... on ThreatActor {
                name
                description
                first_seen
                last_seen
              }
              ... on Tool {
                name
                description
              }
              ... on Vulnerability {
                name
                description
              }
              ... on Incident {
                name
                description
                first_seen
                last_seen
              }
              ... on Event {
                name
                description
                start_time
                stop_time
              }
              ... on Channel {
                name
                description
              }
              ... on Narrative {
                name
                description
              }
              ... on Language {
                name
              }
              ... on StixCyberObservable {
                observable_value
                x_opencti_description
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
        types: fragmentVariables.types,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: containerAddStixCoreObjectsLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(ContainerAddStixCoreObjectsLines);
