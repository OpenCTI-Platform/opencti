import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { compose } from 'ramda';
import { Link } from 'react-router-dom';
import Tooltip from '@mui/material/Tooltip';
import * as R from 'ramda';
import { AutoFix } from 'mdi-material-ui';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import StixCoreRelationshipPopover from './StixCoreRelationshipPopover';
import { resolveLink } from '../../../../utils/Entity';
import StixCoreRelationshipCreationFromRelation from './StixCoreRelationshipCreationFromRelation';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '-5px 0 0 0',
    padding: '10px 0 10px 0',
    borderRadius: 6,
  },
  list: {
    padding: 0,
  },
  avatar: {
    width: 24,
    height: 24,
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    width: 24,
    height: 24,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

class StixCoreRelationshipStixCoreRelationshipsLinesContainer extends Component {
  render() {
    const { t, classes, entityId, data, paginationOptions } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Linked entities')}
        </Typography>
        <Security
          needs={[KNOWLEDGE_KNUPDATE]}
          placeholder={<div style={{ height: 29 }} />}
        >
          <StixCoreRelationshipCreationFromRelation
            entityId={entityId}
            paddingRight={220}
            variant="inLine"
            paginationOptions={paginationOptions}
          />
        </Security>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <List classes={{ root: classes.list }}>
            {data.stixCoreRelationships.edges.map(
              (stixCoreRelationshipEdge) => {
                const stixCoreRelationship = stixCoreRelationshipEdge.node;
                const remoteNode = stixCoreRelationship.from
                  && stixCoreRelationship.from.id === entityId
                  ? stixCoreRelationship.to
                  : stixCoreRelationship.from;
                const restricted = stixCoreRelationship.from === null || remoteNode === null;
                const link = `${resolveLink(remoteNode.entity_type)}/${
                  remoteNode.id
                }`;
                return (
                  <ListItem
                    key={stixCoreRelationship.id}
                    dense={true}
                    divider={true}
                    button={true}
                    component={Link}
                    to={link}
                  >
                    <ListItemIcon>
                      <ItemIcon
                        type={
                          !restricted ? remoteNode.entity_type : 'restricted'
                        }
                      />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        remoteNode.observable_value
                          ? remoteNode.observable_value
                          : remoteNode.name
                      }
                      secondary={t(`entity_${remoteNode.entity_type}`)}
                    />
                    <ListItemSecondaryAction>
                      {stixCoreRelationship.is_inferred ? (
                        <Tooltip
                          title={
                            t('Inferred knowledge based on the rule ')
                            + R.head(stixCoreRelationship.x_opencti_inferences)
                              .rule.name
                          }
                        >
                          <AutoFix
                            fontSize="small"
                            style={{ marginLeft: -30 }}
                            color="secondary"
                          />
                        </Tooltip>
                      ) : (
                        <StixCoreRelationshipPopover
                          stixCoreRelationshipId={stixCoreRelationship.id}
                          paginationOptions={paginationOptions}
                        />
                      )}
                    </ListItemSecondaryAction>
                  </ListItem>
                );
              },
            )}
          </List>
        </Paper>
      </div>
    );
  }
}

StixCoreRelationshipStixCoreRelationshipsLinesContainer.propTypes = {
  entityId: PropTypes.string,
  paginationOptions: PropTypes.object,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const stixCoreRelationshipStixCoreRelationshipsLinesQuery = graphql`
  query StixCoreRelationshipStixCoreRelationshipsLinesQuery(
    $elementId: [String]
    $relationship_type: [String]
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreRelationshipsOrdering
    $orderMode: OrderingMode
  ) {
    ...StixCoreRelationshipStixCoreRelationshipsLines_data
      @arguments(
        elementId: $elementId
        relationship_type: $relationship_type
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const StixCoreRelationshipStixCoreRelationshipsLines = createPaginationContainer(
  StixCoreRelationshipStixCoreRelationshipsLinesContainer,
  {
    data: graphql`
        fragment StixCoreRelationshipStixCoreRelationshipsLines_data on Query
        @argumentDefinitions(
          elementId: { type: "[String]" }
          relationship_type: { type: "[String]" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: {
            type: "StixCoreRelationshipsOrdering"
            defaultValue: start_time
          }
          orderMode: { type: "OrderingMode", defaultValue: asc }
        ) {
          stixCoreRelationships(
            elementId: $elementId
            relationship_type: $relationship_type
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
          ) @connection(key: "Pagination_stixCoreRelationships") {
            edges {
              node {
                id
                is_inferred
                x_opencti_inferences {
                  rule {
                    id
                    name
                  }
                }
                from {
                  ... on StixDomainObject {
                    id
                    entity_type
                    parent_types
                    ... on AttackPattern {
                      name
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
                    ... on Note {
                      attribute_abstract
                      content
                    }
                    ... on Campaign {
                      name
                    }
                    ... on CourseOfAction {
                      name
                    }
                    ... on Individual {
                      name
                    }
                    ... on Organization {
                      name
                    }
                    ... on Sector {
                      name
                    }
                    ... on System {
                      name
                    }
                    ... on Indicator {
                      name
                    }
                    ... on Infrastructure {
                      name
                    }
                    ... on IntrusionSet {
                      name
                    }
                    ... on Position {
                      name
                    }
                    ... on City {
                      name
                    }
                    ... on AdministrativeArea {
                      name
                    }
                    ... on Country {
                      name
                    }
                    ... on Region {
                      name
                    }
                    ... on Malware {
                      name
                    }
                    ... on ThreatActor {
                      name
                    }
                    ... on Tool {
                      name
                    }
                    ... on Vulnerability {
                      name
                    }
                    ... on Incident {
                      name
                    }
                  }
                  ... on StixCyberObservable {
                    id
                    entity_type
                    parent_types
                    observable_value
                  }
                }
                to {
                  ... on StixDomainObject {
                    id
                    entity_type
                    parent_types
                    ... on AttackPattern {
                      name
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
                    ... on Note {
                      attribute_abstract
                      content
                    }
                    ... on Campaign {
                      name
                    }
                    ... on CourseOfAction {
                      name
                    }
                    ... on Individual {
                      name
                    }
                    ... on Organization {
                      name
                    }
                    ... on Sector {
                      name
                    }
                    ... on System {
                      name
                    }
                    ... on Indicator {
                      name
                    }
                    ... on Infrastructure {
                      name
                    }
                    ... on IntrusionSet {
                      name
                    }
                    ... on Position {
                      name
                    }
                    ... on City {
                      name
                    }
                    ... on AdministrativeArea {
                      name
                    }
                    ... on Country {
                      name
                    }
                    ... on Region {
                      name
                    }
                    ... on Malware {
                      name
                    }
                    ... on ThreatActor {
                      name
                    }
                    ... on Tool {
                      name
                    }
                    ... on Vulnerability {
                      name
                    }
                    ... on Incident {
                      name
                    }
                  }
                  ... on StixCyberObservable {
                    id
                    entity_type
                    parent_types
                    observable_value
                  }
                }
              }
            }
            pageInfo {
              endCursor
              hasNextPage
              globalCount
            }
          }
        }
      `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.stixCoreRelationships;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        fromId: fragmentVariables.fromId,
        relationship_type: fragmentVariables.relationship_type,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: stixCoreRelationshipStixCoreRelationshipsLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreRelationshipStixCoreRelationshipsLines);
