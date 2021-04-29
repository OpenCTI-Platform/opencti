import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Accordion from '@material-ui/core/Accordion';
import AccordionDetails from '@material-ui/core/AccordionDetails';
import AccordionSummary from '@material-ui/core/AccordionSummary';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Typography from '@material-ui/core/Typography';
import { ExpandMore } from '@material-ui/icons';
import Checkbox from '@material-ui/core/Checkbox';
import { truncate } from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  container: {
    padding: '20px 0 0 0',
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
  noResult: {
    top: 95,
    left: 16,
    right: 0,
    position: 'absolute',
    color: '#ffffff',
    fontSize: 15,
    zIndex: -5,
    backgroundColor: '#14262c',
  },
});

class StixCoreRelationshipCreationFromEntityLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { expandedPanels: {} };
  }

  handleChangePanel(panelKey, event, expanded) {
    this.setState({
      expandedPanels: R.assoc(panelKey, expanded, this.state.expandedPanels),
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
      t, classes, data, handleSelect, targetEntities,
    } = this.props;
    const targetEntitiesIds = R.pluck('id', targetEntities);
    const stixDomainObjectsNodes = R.map(
      (n) => n.node,
      data.stixDomainObjects.edges,
    );
    const byType = R.groupBy(
      (stixDomainObject) => stixDomainObject.entity_type,
    );
    const stixDomainObjects = byType(stixDomainObjectsNodes);
    const stixDomainObjectsTypes = R.keys(stixDomainObjects);
    let increment = 0;
    return (
      <div className={classes.container}>
        {stixDomainObjectsTypes.length > 0 ? (
          stixDomainObjectsTypes.map((type) => {
            increment += 1;
            return (
              <Accordion
                key={type}
                expanded={this.isExpanded(
                  type,
                  stixDomainObjects[type].length,
                  stixDomainObjectsTypes.length,
                )}
                onChange={this.handleChangePanel.bind(this, type)}
                classes={{ root: classes.expansionPanel }}
                style={{
                  marginBottom:
                    increment === stixDomainObjectsTypes.length
                    && this.isExpanded(
                      type,
                      stixDomainObjects[type].length,
                      stixDomainObjectsTypes.length,
                    )
                      ? 16
                      : 0,
                }}
              >
                <AccordionSummary expandIcon={<ExpandMore />}>
                  <Typography className={classes.heading}>
                    {t(`entity_${type}`)}
                  </Typography>
                  <Typography className={classes.secondaryHeading}>
                    {stixDomainObjects[type].length} {t('entitie(s)')}
                  </Typography>
                </AccordionSummary>
                <AccordionDetails
                  classes={{ root: classes.expansionPanelContent }}
                >
                  <List classes={{ root: classes.list }}>
                    {stixDomainObjects[type].map((stixDomainObject) => (
                      <ListItem
                        key={stixDomainObject.id}
                        classes={{ root: classes.menuItem }}
                        divider={true}
                        button={true}
                        onClick={handleSelect.bind(this, stixDomainObject)}
                      >
                        <ListItemIcon
                          style={{ minWidth: 40 }}
                          onClick={handleSelect.bind(this, stixDomainObject)}
                        >
                          <Checkbox
                            edge="start"
                            checked={R.includes(
                              stixDomainObject.id,
                              targetEntitiesIds,
                            )}
                            disableRipple={true}
                          />
                        </ListItemIcon>
                        <ListItemIcon>
                          <ItemIcon type={type} />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            stixDomainObject.x_mitre_id
                              ? `[${stixDomainObject.x_mitre_id}] ${stixDomainObject.name}`
                              : stixDomainObject.name
                          }
                          secondary={truncate(
                            stixDomainObject.description,
                            100,
                          )}
                        />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>
            );
          })
        ) : (
          <div className={classes.noResult}>
            {t('No entities were found for this search.')}
          </div>
        )}
      </div>
    );
  }
}

StixCoreRelationshipCreationFromEntityLinesContainer.propTypes = {
  handleSelect: PropTypes.func,
  targetEntities: PropTypes.func,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const stixCoreRelationshipCreationFromEntityStixDomainObjectsLinesQuery = graphql`
  query StixCoreRelationshipCreationFromEntityStixDomainObjectsLinesQuery(
    $search: String
    $types: [String]
    $count: Int!
    $cursor: ID
    $orderBy: StixDomainObjectsOrdering
    $orderMode: OrderingMode
  ) {
    ...StixCoreRelationshipCreationFromEntityStixDomainObjectsLines_data
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

const StixCoreRelationshipCreationFromEntityStixDomainObjectsLines = createPaginationContainer(
  StixCoreRelationshipCreationFromEntityLinesContainer,
  {
    data: graphql`
      fragment StixCoreRelationshipCreationFromEntityStixDomainObjectsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        types: { type: "[String]" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "StixDomainObjectsOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        stixDomainObjects(
          search: $search
          types: $types
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_stixDomainObjects") {
          edges {
            node {
              id
              entity_type
              parent_types
              ... on AttackPattern {
                name
                description
                x_mitre_id
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
              ... on Incident {
                name
                description
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
        search: fragmentVariables.search,
        types: fragmentVariables.types,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: stixCoreRelationshipCreationFromEntityStixDomainObjectsLinesQuery,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixCoreRelationshipCreationFromEntityStixDomainObjectsLines);
