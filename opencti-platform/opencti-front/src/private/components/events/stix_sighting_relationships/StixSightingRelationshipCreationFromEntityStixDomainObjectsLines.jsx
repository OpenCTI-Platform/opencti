import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { map, keys, groupBy, assoc, compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Accordion from '@mui/material/Accordion';
import AccordionDetails from '@mui/material/AccordionDetails';
import AccordionSummary from '@mui/material/AccordionSummary';
import List from '@mui/material/List';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import { ExpandMore } from '@mui/icons-material';
import { ListItemButton } from '@mui/material';
import { truncate } from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  container: {
    padding: '20px 0 0 0',
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
    color: theme.palette.text.primary,
    fontSize: 15,
    zIndex: -5,
  },
});

class StixSightingRelationshipCreationFromEntityLinesContainer extends Component {
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
    const { t, classes, data, handleSelect } = this.props;
    const stixDomainObjectsNodes = map(
      (n) => n.node,
      data.stixDomainObjects.edges,
    );
    const byType = groupBy((stixDomainObject) => stixDomainObject.entity_type);
    const stixDomainObjects = byType(stixDomainObjectsNodes);
    const stixDomainObjectsTypes = keys(stixDomainObjects);
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
                elevation={3}
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
                      <ListItemButton
                        key={stixDomainObject.id}
                        classes={{ root: classes.menuItem }}
                        divider={true}
                        onClick={handleSelect.bind(this, stixDomainObject)}
                      >
                        <ListItemIcon>
                          <ItemIcon type={type} />
                        </ListItemIcon>
                        <ListItemText
                          primary={stixDomainObject.name}
                          secondary={truncate(
                            stixDomainObject.description,
                            100,
                          )}
                        />
                      </ListItemButton>
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

StixSightingRelationshipCreationFromEntityLinesContainer.propTypes = {
  handleSelect: PropTypes.func,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const stixSightingRelationshipCreationFromEntityStixDomainObjectsLinesQuery = graphql`
  query StixSightingRelationshipCreationFromEntityStixDomainObjectsLinesQuery(
    $search: String
    $types: [String]
    $count: Int!
    $cursor: ID
    $orderBy: StixDomainObjectsOrdering
    $orderMode: OrderingMode
  ) {
    ...StixSightingRelationshipCreationFromEntityStixDomainObjectsLines_data
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

const StixSightingRelationshipCreationFromEntityStixDomainObjectsLines = createPaginationContainer(
  StixSightingRelationshipCreationFromEntityLinesContainer,
  {
    data: graphql`
        fragment StixSightingRelationshipCreationFromEntityStixDomainObjectsLines_data on Query
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
    query:
        stixSightingRelationshipCreationFromEntityStixDomainObjectsLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixSightingRelationshipCreationFromEntityStixDomainObjectsLines);
