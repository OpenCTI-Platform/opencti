import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { Link } from 'react-router-dom';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVertOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { AutoFix } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import Checkbox from '@mui/material/Checkbox';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ItemConfidence from '../../../../components/ItemConfidence';
import StixCoreRelationshipPopover from './StixCoreRelationshipPopover';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import ItemMarkings from '../../../../components/ItemMarkings';
import ItemEntityType from '../../../../components/ItemEntityType';

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
    paddingRight: 10,
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
      entityId,
      fsd,
      t,
      classes,
      dataColumns,
      node,
      paginationOptions,
      entityLink,
      onToggleEntity,
      selectAll,
      deSelectedElements,
      selectedElements,
      onToggleShiftEntity,
      index,
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
        <ListItemIcon
          classes={{ root: classes.itemIcon }}
          style={{ minWidth: 40 }}
          onClick={(event) => (event.shiftKey
            ? onToggleShiftEntity(index, node)
            : onToggleEntity(node, event))
          }
        >
          <Checkbox
            edge="start"
            checked={
              (selectAll && !(node.id in (deSelectedElements || {})))
              || node.id in (selectedElements || {})
            }
            disableRipple={true}
          />
        </ListItemIcon>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ItemIcon type={node.entity_type} />
        </ListItemIcon>
        <ListItemText
          primary={
            <>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.relationship_type.width }}
              >
                <ItemEntityType
                  entityType={node.relationship_type}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                <ItemEntityType
                  entityType={remoteNode.entity_type}
                  isRestricted={restricted}
                  size='large'
                  showIcon
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{
                  width: dataColumns.name
                    ? dataColumns.name.width
                    : dataColumns.observable_value.width,
                }}
              >
                {!restricted ? getMainRepresentative(remoteNode) : t('Restricted')}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.createdBy.width }}
              >
                {R.pathOr('', ['createdBy', 'name'], node)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.creator.width }}
              >
                {(node.creators ?? []).map((c) => c?.name).join(', ')}
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
                style={{ width: dataColumns.created_at.width }}
              >
                {fsd(node.created_at)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.confidence.width }}
              >
                <ItemConfidence confidence={node.confidence} entityType={node.entity_type} variant="inList" />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectMarking.width }}
              >
                <ItemMarkings
                  variant="inList"
                  markingDefinitions={node.objectMarking ?? []}
                  limit={1}
                />
              </div>
            </>
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
        created_at
        x_opencti_inferences {
          rule {
            id
            name
          }
        }
        createdBy {
          ... on Identity {
            name
          }
        }
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
        creators {
          id
          name
        }
        killChainPhases {
          id
          phase_name
          x_opencti_order
        }
        from {
          ... on StixCoreObject {
            id
            entity_type
            representative {
              main
            }
            parent_types
            created_at
            updated_at
            objectLabel {
              id
              value
              color
            }
            createdBy {
              ... on Identity {
                name
              }
            }
            objectMarking {
              id
              definition_type
              definition
              x_opencti_order
              x_opencti_color
            }
            creators {
              id
              name
            }
          }
          ... on StixDomainObject {
            created
            modified
          }
          ... on StixCoreRelationship {
            id
            entity_type
            parent_types
            created
            created_at
            from {
              ... on StixCoreObject {
                id
                entity_type
                representative {
                  main
                }
                parent_types
                created_at
                updated_at
                objectLabel {
                  id
                  value
                  color
                }
                createdBy {
                  ... on Identity {
                    name
                  }
                }
                objectMarking {
                  id
                  definition_type
                  definition
                  x_opencti_order
                  x_opencti_color
                }
                creators {
                  id
                  name
                }
              }
              ... on StixDomainObject {
                created
                modified
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
              ... on StixCoreObject {
                id
                entity_type
                representative {
                  main
                }
                parent_types
                created_at
                updated_at
                objectLabel {
                  id
                  value
                  color
                }
                createdBy {
                  ... on Identity {
                    name
                  }
                }
                objectMarking {
                  id
                  definition_type
                  definition
                  x_opencti_order
                  x_opencti_color
                }
                creators {
                  id
                  name
                }
              }
              ... on StixDomainObject {
                created
                modified
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
          ... on StixCoreObject {
            id
            entity_type
            representative {
              main
            }
            parent_types
            created_at
            updated_at
            objectLabel {
              id
              value
              color
            }
            createdBy {
              ... on Identity {
                name
              }
            }
            objectMarking {
              id
              definition_type
              definition
              x_opencti_order
              x_opencti_color
            }
            creators {
              id
              name
            }
          }
          ... on StixDomainObject {
            created
            modified
          }
          ... on StixCoreRelationship {
            id
            entity_type
            created
            created_at
            parent_types
            from {
              ... on StixCoreObject {
                id
                entity_type
                representative {
                  main
                }
                parent_types
                created_at
                updated_at
                objectLabel {
                  id
                  value
                  color
                }
                createdBy {
                  ... on Identity {
                    name
                  }
                }
                objectMarking {
                  id
                  definition_type
                  definition
                  x_opencti_order
                  x_opencti_color
                }
                creators {
                  id
                  name
                }
              }
              ... on StixDomainObject {
                created
                modified
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
              ... on StixCoreObject {
                id
                entity_type
                representative {
                  main
                }
                parent_types
                created_at
                updated_at
                objectLabel {
                  id
                  value
                  color
                }
                createdBy {
                  ... on Identity {
                    name
                  }
                }
                objectMarking {
                  id
                  definition_type
                  definition
                  x_opencti_order
                  x_opencti_color
                }
                creators {
                  id
                  name
                }
              }
              ... on StixDomainObject {
                created
                modified
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
        <ListItemIcon
          classes={{ root: classes.itemIconDisabled }}
          style={{ minWidth: 40 }}
        >
          <Checkbox edge="start" disabled={true} disableRipple={true} />
        </ListItemIcon>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
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
                style={{
                  width: dataColumns.name
                    ? dataColumns.name.width
                    : dataColumns.observable_value.width,
                }}
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
                style={{ width: dataColumns.createdBy.width }}
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
                style={{ width: dataColumns.creator.width }}
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
                style={{ width: dataColumns.created_at.width }}
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
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectMarking.width }}
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
