import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import {
  map, filter, head, keys, groupBy, assoc, compose,
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
import { commitMutation } from '../../../relay/environment';
import truncate from '../../../utils/String';
import ItemIcon from '../../../components/ItemIcon';
import inject18n from '../../../components/i18n';

const styles = theme => ({
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

const reportMutationRelationAdd = graphql`
    mutation ReportAddObjectRefsLinesRelationAddMutation($id: ID!, $input: RelationAddInput!) {
        reportEdit(id: $id) {
            relationAdd(input: $input) {
                node {
                    ...ReportKnowledgeGraph_report
                }
            }
        }
    }
`;

export const reportutationRelationDelete = graphql`
    mutation ReportAddObjectRefsLinesRelationDeleteMutation($id: ID!, $relationId: ID!) {
        reportEdit(id: $id) {
            relationDelete(relationId: $relationId) {
                node {
                    ...ReportKnowledgeGraph_report
                }
            }
        }
    }
`;

class ReportAddObjectRefsLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { expandedPanels: {} };
  }

  toggleStixDomain(stixDomain) {
    const { reportId, reportObjectRefs } = this.props;
    const reportObjectRefsIds = map(n => n.node.id, reportObjectRefs);
    const alreadyAdded = reportObjectRefsIds.includes(stixDomain.id);

    if (alreadyAdded) {
      const existingStixDomain = head(filter(n => n.node.id === stixDomain.id, reportObjectRefs));
      commitMutation({
        mutation: reportutationRelationDelete,
        variables: {
          id: reportId,
          relationId: existingStixDomain.relation.id,
        },
      });
    } else {
      const input = {
        fromRole: 'so',
        toId: reportId,
        toRole: 'knowledge_aggregation',
        through: 'object_refs',
      };
      commitMutation({
        mutation: reportMutationRelationAdd,
        variables: {
          id: stixDomain.id,
          input,
        },
      });
    }
  }

  handleChangePanel(panelKey, event, expanded) {
    this.setState({ expandedPanels: assoc(panelKey, expanded, this.state.expandedPanels) });
  }

  isExpanded(type, numberOfEntities) {
    if (this.state.expandedPanels[type] !== undefined) {
      return this.state.expandedPanels[type];
    }
    if (numberOfEntities === 1) {
      return true;
    }
    return false;
  }

  render() {
    const {
      t, classes, data, reportObjectRefs,
    } = this.props;
    const reportObjectRefsIds = map(n => n.node.id, reportObjectRefs);
    const stixDomainEntitiesNodes = map(n => n.node, data.stixDomainEntities.edges);
    const byType = groupBy(stixDomainEntity => stixDomainEntity.type);
    const stixDomainEntities = byType(stixDomainEntitiesNodes);
    const stixDomainEntitiesTypes = keys(stixDomainEntities);

    return (
      <div className={classes.container}>
        {stixDomainEntitiesTypes.map(type => (
          <ExpansionPanel key={type}
                          expanded={this.isExpanded(type, stixDomainEntities[type].length)}
                          onChange={this.handleChangePanel.bind(this, type)}
                          classes={{ root: classes.expansionPanel }}>
            <ExpansionPanelSummary expandIcon={<ExpandMore/>}>
              <Typography className={classes.heading}>{t(`entity_${type}`)}</Typography>
              <Typography className={classes.secondaryHeading}>{stixDomainEntities[type].length} {t('entitie(s)')}</Typography>
            </ExpansionPanelSummary>
            <ExpansionPanelDetails classes={{ root: classes.expansionPanelContent }}>
              <List classes={{ root: classes.list }}>
                {stixDomainEntities[type].map((stixDomainEntity) => {
                  const alreadyAdded = reportObjectRefsIds.includes(stixDomainEntity.id);
                  return (
                    <ListItem
                      key={stixDomainEntity.id}
                      classes={{ root: classes.menuItem }}
                      divider={true}
                      button={true}
                      onClick={this.toggleStixDomain.bind(this, stixDomainEntity)}>
                      <ListItemIcon>
                        {alreadyAdded ? <CheckCircle classes={{ root: classes.icon }}/>
                          : <ItemIcon type={type}/>}
                      </ListItemIcon>
                      <ListItemText
                        primary={stixDomainEntity.name}
                        secondary={truncate(stixDomainEntity.description, 100)}
                      />
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
}

ReportAddObjectRefsLinesContainer.propTypes = {
  reportId: PropTypes.string,
  reportObjectRefs: PropTypes.array,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const reportAddObjectRefsLinesQuery = graphql`
    query ReportAddObjectRefsLinesQuery($search: String, $count: Int!, $cursor: ID, $orderBy: StixDomainEntitiesOrdering, $orderMode: OrderingMode) {
        ...ReportAddObjectRefsLines_data @arguments(search: $search, count: $count, cursor: $cursor, orderBy: $orderBy, orderMode: $orderMode)
    }
`;

const ReportAddObjectRefsLines = createPaginationContainer(
  ReportAddObjectRefsLinesContainer,
  {
    data: graphql`
        fragment ReportAddObjectRefsLines_data on Query @argumentDefinitions(
            search: {type: "String"}
            count: {type: "Int", defaultValue: 25}
            cursor: {type: "ID"}
            orderBy: {type: "StixDomainEntitiesOrdering", defaultValue: ID}
            orderMode: {type: "OrderingMode", defaultValue: "asc"}
        ) {
            stixDomainEntities(search: $search, first: $count, after: $cursor, orderBy: $orderBy, orderMode: $orderMode) @connection(key: "Pagination_stixDomainEntities") {
                edges {
                    node {
                        id
                        type
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

export default compose(
  inject18n,
  withStyles(styles),
)(ReportAddObjectRefsLines);
