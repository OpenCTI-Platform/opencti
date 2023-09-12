import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, graphql } from 'react-relay';
import { assoc, compose, groupBy, keys, map, includes } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Accordion from '@mui/material/Accordion';
import AccordionDetails from '@mui/material/AccordionDetails';
import AccordionSummary from '@mui/material/AccordionSummary';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import { CheckCircle, ExpandMore } from '@mui/icons-material';
import { commitMutation } from '../../../../relay/environment';
import { truncate } from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import inject18n from '../../../../components/i18n';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';

const styles = (theme) => ({
  investigation: {
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
  tooltip: {
    maxWidth: '80%',
    lineHeight: 2,
    padding: 10,
    backgroundColor: '#323232',
  },
});

export const investigationAddStixCoreObjectsLinesRelationAddMutation = graphql`
  mutation InvestigationAddStixCoreObjectsLinesRelationAddMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    workspaceFieldPatch(id: $id, input: $input) {
      id
    }
  }
`;

export const investigationAddStixCoreObjectsLinesRelationDeleteMutation = graphql`
  mutation InvestigationAddStixCoreObjectsLinesRelationDeleteMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    workspaceFieldPatch(id: $id, input: $input) {
      id
    }
  }
`;

export const investigationAddStixCoreObjectsLinesRelationsDeleteMutation = graphql`
  mutation InvestigationAddStixCoreObjectsLinesRelationsDeleteMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    workspaceFieldPatch(id: $id, input: $input) {
      id
    }
  }
`;

class InvestigationAddStixCoreObjectsLinesInvestigation extends Component {
  constructor(props) {
    super(props);
    this.state = {
      expandedPanels: {},
      addedStixCoreObjects: (props.workspaceStixCoreObjects || []).map((n) => n.node.id),
    };
  }

  toggleStixCoreObject(stixCoreObject) {
    const { workspaceId, onAdd, onDelete } = this.props;
    const { addedStixCoreObjects } = this.state;
    const alreadyAdded = includes(stixCoreObject.id, addedStixCoreObjects);
    if (alreadyAdded) {
      commitMutation({
        mutation: investigationAddStixCoreObjectsLinesRelationDeleteMutation,
        variables: {
          id: workspaceId,
          input: {
            key: 'investigated_entities_ids',
            operation: 'remove',
            value: stixCoreObject.id,
          },
        },
        onCompleted: () => {
          this.setState({
            addedStixCoreObjects: addedStixCoreObjects
              .filter((n) => n !== stixCoreObject.id),
          });
          if (typeof onDelete === 'function') {
            onDelete(stixCoreObject);
          }
        },
      });
    } else {
      commitMutation({
        mutation: investigationAddStixCoreObjectsLinesRelationAddMutation,
        variables: {
          id: workspaceId,
          input: {
            key: 'investigated_entities_ids',
            operation: 'add',
            value: stixCoreObject.id,
          },
        },
        onCompleted: () => {
          this.setState({
            addedStixCoreObjects: [...addedStixCoreObjects, stixCoreObject.id],
          });
          if (typeof onAdd === 'function') {
            onAdd(stixCoreObject);
          }
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
    const { t, classes, data, fd } = this.props;
    const { addedStixCoreObjects } = this.state;
    const stixCoreObjectsNodes = map((n) => n.node, data.stixCoreObjects.edges);
    const byType = groupBy((stixCoreObject) => stixCoreObject.entity_type);
    const stixCoreObjects = byType(stixCoreObjectsNodes);
    const stixCoreObjectsTypes = keys(stixCoreObjects);
    return (
      <div className={classes.investigation}>
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
                    const alreadyAdded = includes(stixCoreObject.id, addedStixCoreObjects);
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
                          }${
                            stixCoreObject.name
                            || stixCoreObject.observable_value
                            || stixCoreObject.attribute_abstract
                            || stixCoreObject.result_name
                            || truncate(stixCoreObject.content, 30)
                            || stixCoreObject.opinion
                            || `${fd(stixCoreObject.first_observed)} - ${fd(
                              stixCoreObject.last_observed,
                            )}`
                          }`}
                          secondary={
                            <MarkdownDisplay
                              content={
                                stixCoreObject.description
                                || fd(stixCoreObject.created_at)
                              }
                              limit={200}
                              remarkGfmPlugin={true}
                              commonmark={true}
                            />
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

InvestigationAddStixCoreObjectsLinesInvestigation.propTypes = {
  workspaceId: PropTypes.string,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  paginationOptions: PropTypes.object,
  workspaceStixCoreObjects: PropTypes.array,
  onAdd: PropTypes.func,
  onDelete: PropTypes.func,
};

export const investigationAddStixCoreObjectsLinesQuery = graphql`
  query InvestigationAddStixCoreObjectsLinesQuery(
    $types: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
  ) {
    ...InvestigationAddStixCoreObjectsLines_data
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

const InvestigationAddStixCoreObjectsLines = createPaginationContainer(
  InvestigationAddStixCoreObjectsLinesInvestigation,
  {
    data: graphql`
      fragment InvestigationAddStixCoreObjectsLines_data on Query
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
                    definition_type
                    definition
                    x_opencti_order
                    x_opencti_color
                  }
                }
              }
              ... on StixDomainObject {
                created
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
                content
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
              ... on Grouping {
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
              ... on AdministrativeArea {
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
              ... on MalwareAnalysis {
                result_name
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
              ... on DataComponent {
                name
              }
              ... on DataSource {
                name
              }
              ... on Case {
                name
              }
              ... on StixCyberObservable {
                observable_value
                x_opencti_description
              }
              ... on StixFile {
                observableName: name
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
    query: investigationAddStixCoreObjectsLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(InvestigationAddStixCoreObjectsLines);
