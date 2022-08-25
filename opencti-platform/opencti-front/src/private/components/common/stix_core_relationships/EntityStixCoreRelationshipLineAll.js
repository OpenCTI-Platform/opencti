import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { Link } from 'react-router-dom';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVertOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { AutoFix } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ItemConfidence from '../../../../components/ItemConfidence';
import StixCoreRelationshipPopover from './StixCoreRelationshipPopover';
import { defaultType, defaultValue } from '../../../../utils/Graph';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 5,
  },
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

class EntityStixCoreRelationshipLineAllComponent extends Component {
  render() {
    const {
      fsd,
      t,
      classes,
      dataColumns,
      node,
      paginationOptions,
      entityId,
      entityLink,
    } = this.props;
    const remoteNode = node.from && node.from.id === entityId ? node.to : node.from;
    const restricted = node.from === null || node.to === null;
    const link = `${entityLink}/relations/${node.id}`;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={link}
        disabled={restricted}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ItemIcon
            type={!restricted ? remoteNode.entity_type : 'restricted'}
          />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.relationship_type.width }}
              >
                {t(`relationship_${node.relationship_type}`)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {!restricted ? defaultValue(remoteNode) : t('Restricted')}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                {!restricted ? defaultType(remoteNode, t) : t('Restricted')}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.start_time.width }}
              >
                {fsd(node.start_time)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.stop_time.width }}
              >
                {fsd(node.stop_time)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created.width }}
              >
                {fsd(node.created)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.confidence.width }}
              >
                <ItemConfidence confidence={node.confidence} variant="inList" />
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          {node.is_inferred ? (
            <Tooltip
              title={
                t('Inferred knowledge based on the rule ')
                + R.head(node.x_opencti_inferences).rule.name
              }
            >
              <AutoFix fontSize="small" style={{ marginLeft: -30 }} />
            </Tooltip>
          ) : (
            <StixCoreRelationshipPopover
              stixCoreRelationshipId={node.id}
              paginationOptions={paginationOptions}
              disabled={restricted}
            />
          )}
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

EntityStixCoreRelationshipLineAllComponent.propTypes = {
  dataColumns: PropTypes.object,
  entityId: PropTypes.string,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
};

const EntityStixCoreRelationshipLineAllFragment = createFragmentContainer(
  EntityStixCoreRelationshipLineAllComponent,
  {
    node: graphql`
      fragment EntityStixCoreRelationshipLineAll_node on StixCoreRelationship {
        id
        entity_type
        parent_types
        relationship_type
        confidence
        start_time
        stop_time
        description
        is_inferred
        created
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
            created_at
            updated_at
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
          ... on AttackPattern {
            name
            description
            x_mitre_id
            killChainPhases {
              edges {
                node {
                  id
                  phase_name
                  x_opencti_order
                }
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
          ... on StixCyberObservable {
            id
            entity_type
            parent_types
            observable_value
            objectMarking {
              edges {
                node {
                  id
                  definition
                }
              }
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
          ... on Indicator {
            id
            name
            pattern_type
            pattern_version
            description
            valid_from
            valid_until
            x_opencti_score
            x_opencti_main_observable_type
            created
            objectMarking {
              edges {
                node {
                  id
                  definition
                }
              }
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
          ... on StixCoreRelationship {
            id
            entity_type
            parent_types
            created
            created_at
            from {
              ... on StixDomainObject {
                id
                entity_type
                parent_types
                created_at
                updated_at
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
              ... on AttackPattern {
                name
                description
                x_mitre_id
                killChainPhases {
                  edges {
                    node {
                      id
                      phase_name
                      x_opencti_order
                    }
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
              ... on StixCyberObservable {
                id
                entity_type
                parent_types
                observable_value
                objectMarking {
                  edges {
                    node {
                      id
                      definition
                    }
                  }
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
              ... on Indicator {
                id
                name
                pattern_type
                pattern_version
                description
                valid_from
                valid_until
                x_opencti_score
                x_opencti_main_observable_type
                created
                objectMarking {
                  edges {
                    node {
                      id
                      definition
                    }
                  }
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
              ... on StixCoreRelationship {
                id
                entity_type
                parent_types
                created
                created_at
              }
            }
            to {
              ... on StixDomainObject {
                id
                entity_type
                parent_types
                created_at
                updated_at
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
              ... on AttackPattern {
                name
                description
                x_mitre_id
                killChainPhases {
                  edges {
                    node {
                      id
                      phase_name
                      x_opencti_order
                    }
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
              ... on StixCyberObservable {
                id
                entity_type
                parent_types
                observable_value
                objectMarking {
                  edges {
                    node {
                      id
                      definition
                    }
                  }
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
              ... on Indicator {
                id
                name
                pattern_type
                pattern_version
                description
                valid_from
                valid_until
                x_opencti_score
                x_opencti_main_observable_type
                created
                objectMarking {
                  edges {
                    node {
                      id
                      definition
                    }
                  }
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
              ... on StixCoreRelationship {
                id
                entity_type
                created
                created_at
                parent_types
              }
            }
          }
        }
        to {
          ... on StixDomainObject {
            id
            entity_type
            parent_types
            created_at
            updated_at
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
          ... on AttackPattern {
            name
            description
            x_mitre_id
            killChainPhases {
              edges {
                node {
                  id
                  phase_name
                  x_opencti_order
                }
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
          ... on StixCyberObservable {
            id
            entity_type
            parent_types
            observable_value
            objectMarking {
              edges {
                node {
                  id
                  definition
                }
              }
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
          ... on Indicator {
            id
            name
            pattern_type
            pattern_version
            description
            valid_from
            valid_until
            x_opencti_score
            x_opencti_main_observable_type
            created
            objectMarking {
              edges {
                node {
                  id
                  definition
                }
              }
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
          ... on StixCoreRelationship {
            id
            entity_type
            created
            created_at
            parent_types
            from {
              ... on StixDomainObject {
                id
                entity_type
                parent_types
                created_at
                updated_at
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
              ... on AttackPattern {
                name
                description
                x_mitre_id
                killChainPhases {
                  edges {
                    node {
                      id
                      phase_name
                      x_opencti_order
                    }
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
              ... on StixCyberObservable {
                id
                entity_type
                parent_types
                observable_value
                objectMarking {
                  edges {
                    node {
                      id
                      definition
                    }
                  }
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
              ... on Indicator {
                id
                name
                pattern_type
                pattern_version
                description
                valid_from
                valid_until
                x_opencti_score
                x_opencti_main_observable_type
                created
                objectMarking {
                  edges {
                    node {
                      id
                      definition
                    }
                  }
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
              ... on StixCoreRelationship {
                id
                entity_type
                parent_types
                created
                created_at
              }
            }
            to {
              ... on StixDomainObject {
                id
                entity_type
                parent_types
                created_at
                updated_at
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
              ... on AttackPattern {
                name
                description
                x_mitre_id
                killChainPhases {
                  edges {
                    node {
                      id
                      phase_name
                      x_opencti_order
                    }
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
              ... on StixCyberObservable {
                id
                entity_type
                parent_types
                observable_value
                objectMarking {
                  edges {
                    node {
                      id
                      definition
                    }
                  }
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
              ... on Indicator {
                id
                name
                pattern_type
                pattern_version
                description
                valid_from
                valid_until
                x_opencti_score
                x_opencti_main_observable_type
                created
                objectMarking {
                  edges {
                    node {
                      id
                      definition
                    }
                  }
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
              ... on StixCoreRelationship {
                id
                entity_type
                created
                created_at
                parent_types
              }
            }
          }
        }
        killChainPhases {
          edges {
            node {
              id
              phase_name
              x_opencti_order
            }
          }
        }
      }
    `,
  },
);

export const EntityStixCoreRelationshipLineAll = R.compose(
  inject18n,
  withStyles(styles),
)(EntityStixCoreRelationshipLineAllFragment);

class EntityStixCoreRelationshipLineAllDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Skeleton
            animation="wave"
            variant="circular"
            width={30}
            height={30}
          />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.relationship_type.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.start_time.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={140}
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.stop_time.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={140}
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={140}
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.confidence.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={100}
                  height="100%"
                />
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
          <MoreVertOutlined />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

EntityStixCoreRelationshipLineAllDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const EntityStixCoreRelationshipLineAllDummy = R.compose(
  inject18n,
  withStyles(styles),
)(EntityStixCoreRelationshipLineAllDummyComponent);
