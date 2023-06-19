import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { map, keys, groupBy, assoc, compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Accordion from '@mui/material/Accordion';
import AccordionDetails from '@mui/material/AccordionDetails';
import AccordionSummary from '@mui/material/AccordionSummary';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Typography from '@mui/material/Typography';
import { ExpandMore } from '@mui/icons-material';
import { Link } from 'react-router-dom';
import { truncate } from '../../../../utils/String';
import { resolveLink } from '../../../../utils/Entity';
import ItemIcon from '../../../../components/ItemIcon';
import inject18n from '../../../../components/i18n';
import StixCoreObjectLabels from '../stix_core_objects/StixCoreObjectLabels';

const styles = (theme) => ({
  container: {
    padding: '0 0 20px 0',
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
  icon: {
    color: theme.palette.primary.main,
  },
  noResult: {
    top: 180,
    left: 50,
    right: 0,
    textAlign: 'center',
    position: 'absolute',
    color: theme.palette.text.primary,
    fontSize: 15,
    zIndex: -5,
  },
});

class StixDomainObjectsContainer extends Component {
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
    const { t, classes, data, fd } = this.props;
    const stixDomainObjectsNodes = map(
      (n) => n.node,
      data.stixDomainObjects.edges,
    );
    const byType = groupBy((stixDomainObject) => stixDomainObject.entity_type);
    const stixDomainObjects = byType(stixDomainObjectsNodes);
    const stixDomainObjectsTypes = keys(stixDomainObjects);
    if (stixDomainObjectsTypes.length !== 0) {
      return (
        <div className={classes.container}>
          {stixDomainObjectsTypes.map((type) => (
            <Accordion
              key={type}
              expanded={this.isExpanded(
                type,
                stixDomainObjects[type].length,
                stixDomainObjectsTypes.length,
              )}
              onChange={this.handleChangePanel.bind(this, type)}
              elevation={3}
            >
              <AccordionSummary
                expandIcon={<ExpandMore />}
                className={classes.summary}
              >
                <Typography className={classes.heading}>
                  {t(`entity_${type}`)}
                </Typography>
                <Typography classes={{ root: classes.secondaryHeading }}>
                  {stixDomainObjects[type].length}{' '}
                  {stixDomainObjects[type].length < 2
                    ? t('entity')
                    : t('entities')}
                </Typography>
              </AccordionSummary>
              <AccordionDetails
                classes={{ root: classes.expansionPanelContent }}
              >
                <List classes={{ root: classes.list }}>
                  {stixDomainObjects[type].map((stixDomainObject) => {
                    const link = resolveLink(stixDomainObject.entity_type);
                    if (link) {
                      return (
                        <ListItem
                          key={stixDomainObject.id}
                          divider={true}
                          button={true}
                          component={Link}
                          to={`${link}/${stixDomainObject.id}`}
                        >
                          <ListItemIcon classes={{ root: classes.itemIcon }}>
                            <ItemIcon type={type} />
                          </ListItemIcon>
                          <ListItemText
                            primary={truncate(
                              stixDomainObject.x_mitre_id
                                ? `[${stixDomainObject.x_mitre_id}] ${stixDomainObject.name}`
                                : stixDomainObject.name
                                    || stixDomainObject.attribute_abstract
                                    || stixDomainObject.content
                                    || stixDomainObject.opinion
                                    || `${fd(
                                      stixDomainObject.first_observed,
                                    )} - ${fd(stixDomainObject.last_observed)}`,
                              100,
                            )}
                            secondary={truncate(
                              stixDomainObject.description,
                              150,
                            )}
                          />
                          <ListItemSecondaryAction>
                            <StixCoreObjectLabels
                              labels={stixDomainObject.objectLabel}
                              variant="inSearch"
                            />
                          </ListItemSecondaryAction>
                        </ListItem>
                      );
                    }
                    return (
                      <ListItem
                        key={stixDomainObject.id}
                        divider={true}
                        button={false}
                      >
                        <ListItemIcon classes={{ root: classes.itemIcon }}>
                          <ItemIcon type={type} />
                        </ListItemIcon>
                        <ListItemText
                          primary={truncate(stixDomainObject.name, 100)}
                          secondary={truncate(
                            stixDomainObject.description,
                            150,
                          )}
                        />
                        <ListItemSecondaryAction>
                          <StixCoreObjectLabels
                            labels={stixDomainObject.objectLabel}
                            variant="inSearch"
                          />
                        </ListItemSecondaryAction>
                      </ListItem>
                    );
                  })}
                </List>
              </AccordionDetails>
            </Accordion>
          ))}
        </div>
      );
    }
    return (
      <div className={classes.noResult}>
        {t('No entities were found for this search.')}
      </div>
    );
  }
}

StixDomainObjectsContainer.propTypes = {
  reportId: PropTypes.string,
  reportObjectRefs: PropTypes.array,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  fd: PropTypes.func,
};

export const stixDomainObjectsLinesSubTypesQuery = graphql`
  query StixDomainObjectsLinesSubTypesQuery(
    $type: String!
    $includeParents: Boolean
  ) {
    subTypes(type: $type, includeParents: $includeParents) {
      edges {
        node {
          id
          label
        }
      }
    }
  }
`;

export const stixDomainObjectsLinesQuery = graphql`
  query StixDomainObjectsLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixDomainObjectsOrdering
    $orderMode: OrderingMode
    $filters: [StixDomainObjectsFiltering]
  ) {
    ...StixDomainObjectsLines_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      )
  }
`;

export const stixDomainObjectsLinesSearchQuery = graphql`
  query StixDomainObjectsLinesSearchQuery(
    $search: String
    $types: [String]
    $count: Int
    $filters: [StixDomainObjectsFiltering]
  ) {
    stixDomainObjects(
      search: $search
      types: $types
      first: $count
      filters: $filters
    ) {
      edges {
        node {
          id
          entity_type
          standard_id
          ... on AttackPattern {
            name
            description
            x_mitre_id
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
          }
          ... on Grouping {
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
          ... on System {
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
          ... on CaseIncident {
            name
            description
          }
          ... on CaseRfi {
            name
            description
          }
          ... on CaseRft {
            name
            description
          }
          ... on Task {
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
          ... on Incident {
            name
            description
          }
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
                definition
                definition_type
                definition
                x_opencti_order
                x_opencti_color
              }
            }
          }
        }
      }
    }
  }
`;

const StixDomainObjectsLines = createPaginationContainer(
  StixDomainObjectsContainer,
  {
    data: graphql`
      fragment StixDomainObjectsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "StixDomainObjectsOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[StixDomainObjectsFiltering]" }
      ) {
        stixDomainObjects(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_stixDomainObjects") {
          edges {
            node {
              id
              entity_type
              id
              entity_type
              ... on AttackPattern {
                name
                description
                x_mitre_id
              }
              ... on Campaign {
                name
                description
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
              ... on Incident {
                name
                description
              }
              ... on Event {
                name
                description
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
              ... on DataComponent {
                name
              }
              ... on DataSource {
                name
              }
              ... on Case {
                name
              }
              ... on CaseIncident {
                name
              }
              ... on CaseRfi {
                name
              }
              ... on CaseRft {
                name
              }
              ... on Task {
                name
              }
              objectLabel {
                edges {
                  node {
                    id
                    value
                    color
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
      return props.data && props.data.stixDomainObjects;
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
    query: stixDomainObjectsLinesQuery,
  },
);

export default compose(inject18n, withStyles(styles))(StixDomainObjectsLines);
