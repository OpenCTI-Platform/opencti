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
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import Typography from '@material-ui/core/Typography';
import { ExpandMore } from '@material-ui/icons';
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
  icon: {
    color: theme.palette.primary.main,
  },
  noResult: {
    top: 180,
    left: 50,
    right: 0,
    textAlign: 'center',
    position: 'absolute',
    color: '#ffffff',
    fontSize: 15,
    zIndex: -5,
    backgroundColor: theme.palette.background.default,
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
    if (numberOfTypes === 1) {
      return true;
    }
    return false;
  }

  render() {
    const { t, classes, data } = this.props;
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
            <ExpansionPanel
              key={type}
              expanded={this.isExpanded(
                type,
                stixDomainObjects[type].length,
                stixDomainObjectsTypes.length,
              )}
              onChange={this.handleChangePanel.bind(this, type)}
              classes={{ root: classes.expansionPanel }}
            >
              <ExpansionPanelSummary
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
              </ExpansionPanelSummary>
              <ExpansionPanelDetails
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
                            primary={stixDomainObject.name}
                            secondary={truncate(
                              stixDomainObject.description,
                              200,
                            )}
                          />
                          <ListItemSecondaryAction>
                            <StixCoreObjectLabels
                              labels={stixDomainObject.labels}
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
                          primary={stixDomainObject.name}
                          secondary={truncate(
                            stixDomainObject.description,
                            200,
                          )}
                        />
                        <ListItemSecondaryAction>
                          <StixCoreObjectLabels
                            labels={stixDomainObject.labels}
                            variant="inSearch"
                          />
                        </ListItemSecondaryAction>
                      </ListItem>
                    );
                  })}
                </List>
              </ExpansionPanelDetails>
            </ExpansionPanel>
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
};

export const stixDomainObjectsLinesQuery = graphql`
  query StixDomainObjectsLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixDomainObjectsOrdering
    $orderMode: OrderingMode
  ) {
    ...StixDomainObjectsLines_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

export const stixDomainObjectsLinesSearchQuery = graphql`
  query StixDomainObjectsLinesSearchQuery($search: String, $types: [String]) {
    stixDomainObjects(search: $search, types: $types) {
      edges {
        node {
          id
          name
          description
          entity_type
          createdBy {
            node {
              id
              name
            }
          }
          objectMarking {
            edges {
              node {
                definition
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
          orderBy: { type: "StixDomainObjectsOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
        ) {
        stixDomainObjects(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_stixDomainObjects") {
          edges {
            node {
              id
              entity_type
              name
              description
              ... on StixEntity {
                labels {
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
