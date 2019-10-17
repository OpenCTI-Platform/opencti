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
import { truncate } from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import inject18n from '../../../../components/i18n';

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

class StixRelationCreationFromEntityLinesContainer extends Component {
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
    const {
      t, classes, data, handleSelect,
    } = this.props;
    const stixDomainEntitiesNodes = map(
      (n) => n.node,
      data.stixDomainEntities.edges,
    );
    const byType = groupBy((stixDomainEntity) => stixDomainEntity.entity_type);
    const stixDomainEntities = byType(stixDomainEntitiesNodes);
    const stixDomainEntitiesTypes = keys(stixDomainEntities);

    return (
      <div className={classes.container}>
        {stixDomainEntitiesTypes.length > 0 ? stixDomainEntitiesTypes.map((type) => (
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
              classes={{ root: classes.expansionPanelContent }}>
              <List classes={{ root: classes.list }}>
                {stixDomainEntities[type].map((stixDomainEntity) => (
                  <ListItem
                    key={stixDomainEntity.id}
                    classes={{ root: classes.menuItem }}
                    divider={true}
                    button={true}
                    onClick={handleSelect.bind(this, stixDomainEntity)}
                  >
                    <ListItemIcon>
                      <ItemIcon type={type} />
                    </ListItemIcon>
                    <ListItemText
                      primary={stixDomainEntity.name}
                      secondary={truncate(stixDomainEntity.description, 100)}
                    />
                  </ListItem>
                ))}
              </List>
            </ExpansionPanelDetails>
          </ExpansionPanel>
        )) : <div style={{ paddingLeft: 20 }}>{t('No entities were found for this search.')}</div>}
      </div>
    );
  }
}

StixRelationCreationFromEntityLinesContainer.propTypes = {
  handleSelect: PropTypes.func,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const stixRelationCreationFromEntityLinesQuery = graphql`
  query StixRelationCreationFromEntityLinesQuery(
    $search: String
    $types: [String]
    $count: Int!
    $cursor: ID
    $orderBy: StixDomainEntitiesOrdering
    $orderMode: OrderingMode
  ) {
    ...StixRelationCreationFromEntityLines_data
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

const StixRelationCreationFromEntityLines = createPaginationContainer(
  StixRelationCreationFromEntityLinesContainer,
  {
    data: graphql`
      fragment StixRelationCreationFromEntityLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          types: { type: "[String]" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "StixDomainEntitiesOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
        ) {
        stixDomainEntities(
          search: $search
          types: $types
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
        search: fragmentVariables.search,
        types: fragmentVariables.types,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: stixRelationCreationFromEntityLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixRelationCreationFromEntityLines);
