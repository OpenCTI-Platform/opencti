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
import Typography from '@mui/material/Typography';
import { ExpandMore, CheckCircle } from '@mui/icons-material';
import { ConnectionHandler } from 'relay-runtime';
import { commitMutation } from '../../../../relay/environment';
import ItemIcon from '../../../../components/ItemIcon';
import inject18n from '../../../../components/i18n';

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
    width: '100M',
  },
  icon: {
    color: theme.palette.primary.main,
  },
});

export const indicatorMutationRelationAdd = graphql`
  mutation IndicatorAddObservablesLinesRelationAddMutation(
    $input: StixCoreRelationshipAddInput!
  ) {
    stixCoreRelationshipAdd(input: $input) {
      id
      from {
        ...IndicatorObservables_indicator
      }
    }
  }
`;

export const indicatorMutationRelationDelete = graphql`
  mutation IndicatorAddObservablesLinesRelationDeleteMutation(
    $fromId: StixRef!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixCoreRelationshipDelete(
      fromId: $fromId
      toId: $toId
      relationship_type: $relationship_type
    )
  }
`;

class IndicatorAddObservablesLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { expandedPanels: {} };
  }

  toggleStixCyberObservable(stixCyberObservable) {
    const { indicatorId, indicatorObservables } = this.props;
    const indicatorObservablesIds = map((n) => n.node.id, indicatorObservables);
    const alreadyAdded = indicatorObservablesIds.includes(
      stixCyberObservable.id,
    );
    if (alreadyAdded) {
      commitMutation({
        mutation: indicatorMutationRelationDelete,
        variables: {
          fromId: indicatorId,
          toId: stixCyberObservable.id,
          relationship_type: 'based-on',
        },
        updater: (store) => {
          const conn = ConnectionHandler.getConnection(
            store.get(indicatorId),
            'Pagination_observables',
          );
          ConnectionHandler.deleteNode(conn, stixCyberObservable.id);
        },
      });
    } else {
      const input = {
        fromId: indicatorId,
        toId: stixCyberObservable.id,
        relationship_type: 'based-on',
      };
      commitMutation({
        mutation: indicatorMutationRelationAdd,
        variables: { input },
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
    const { t, classes, data, indicatorObservables } = this.props;
    const indicatorObservablesIds = map((n) => n.node.id, indicatorObservables);
    const stixCyberObservablesNodes = map(
      (n) => n.node,
      data.stixCyberObservables.edges,
    );
    const byType = groupBy(
      (stixCyberObservable) => stixCyberObservable.entity_type,
    );
    const stixCyberObservables = byType(stixCyberObservablesNodes);
    const stixCyberObservablesTypes = keys(stixCyberObservables);

    return (
      <div className={classes.container}>
        {stixCyberObservablesTypes.length > 0 ? (
          stixCyberObservablesTypes.map((type) => (
            <Accordion
              key={type}
              expanded={this.isExpanded(
                type,
                stixCyberObservables[type].length,
                stixCyberObservablesTypes.length,
              )}
              onChange={this.handleChangePanel.bind(this, type)}
              elevation={3}
            >
              <AccordionSummary expandIcon={<ExpandMore />}>
                <Typography className={classes.heading}>
                  {t(`entity_${type}`)}
                </Typography>
                <Typography className={classes.secondaryHeading}>
                  {stixCyberObservables[type].length} {t('entitie(s)')}
                </Typography>
              </AccordionSummary>
              <AccordionDetails
                classes={{ root: classes.expansionPanelContent }}
              >
                <List classes={{ root: classes.list }}>
                  {stixCyberObservables[type].map((stixCyberObservable) => {
                    const alreadyAdded = indicatorObservablesIds.includes(
                      stixCyberObservable.id,
                    );
                    return (
                      <ListItem
                        key={stixCyberObservable.id}
                        classes={{ root: classes.menuItem }}
                        divider={true}
                        button={true}
                        onClick={this.toggleStixCyberObservable.bind(
                          this,
                          stixCyberObservable,
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
                          primary={stixCyberObservable.observable_value}
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

IndicatorAddObservablesLinesContainer.propTypes = {
  indicatorId: PropTypes.string,
  indicatorObservables: PropTypes.array,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const indicatorAddObservablesLinesQuery = graphql`
  query IndicatorAddObservablesLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCyberObservablesOrdering
    $orderMode: OrderingMode
  ) {
    ...IndicatorAddObservablesLines_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const IndicatorAddObservablesLines = createPaginationContainer(
  IndicatorAddObservablesLinesContainer,
  {
    data: graphql`
      fragment IndicatorAddObservablesLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }

        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: {
          type: "StixCyberObservablesOrdering"
          defaultValue: created_at
        }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        stixCyberObservables(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_stixCyberObservables") {
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
      return props.data && props.data.stixCyberObservables;
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
    query: indicatorAddObservablesLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(IndicatorAddObservablesLines);
