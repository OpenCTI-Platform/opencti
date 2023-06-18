import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVertOutlined } from '@mui/icons-material';
import Chip from '@mui/material/Chip';
import { Link } from 'react-router-dom';
import Skeleton from '@mui/material/Skeleton';
import Tooltip from '@mui/material/Tooltip';
import { AutoFix } from 'mdi-material-ui';
import Checkbox from '@mui/material/Checkbox';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ItemConfidence from '../../../../components/ItemConfidence';
import StixSightingRelationshipPopover from './StixSightingRelationshipPopover';
import { truncate } from '../../../../utils/String';
import ItemStatus from '../../../../components/ItemStatus';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  positive: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    backgroundColor: 'rgba(244, 67, 54, 0.08)',
    color: '#f44336',
    textTransform: 'uppercase',
    borderRadius: '0',
  },
  negative: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    backgroundColor: 'rgba(76, 175, 80, 0.08)',
    color: '#4caf50',
    textTransform: 'uppercase',
    borderRadius: '0',
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

class StixSightingRelationshipLineComponent extends Component {
  render() {
    const {
      nsdt,
      t,
      fd,
      classes,
      dataColumns,
      node,
      paginationOptions,
      selectedElements,
      deSelectedElements,
      selectAll,
      onToggleEntity,
      onToggleShiftEntity,
      index,
    } = this.props;
    const entityFrom = node.from;
    const entityTo = node.to;
    const restrictedFrom = entityFrom === null;
    const restrictedTo = entityTo === null;
    const link = `/dashboard/events/sightings/${node.id}`;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={link}
      >
        <ListItemIcon
          classes={{ root: classes.itemIcon }}
          style={{ minWidth: 40 }}
          onClick={(event) => (event.shiftKey
            ? onToggleShiftEntity(index, node, event)
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
          <ItemIcon
            type={!restrictedFrom ? entityFrom.entity_type : 'restricted'}
          />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.x_opencti_negative.width }}
              >
                <Chip
                  classes={{
                    root: node.x_opencti_negative
                      ? classes.negative
                      : classes.positive,
                  }}
                  label={
                    node.x_opencti_negative
                      ? t('False positive')
                      : t('True positive')
                  }
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{
                  width: dataColumns.attribute_count.width,
                  fontWeight: 'bold',
                }}
              >
                {node.attribute_count}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {!restrictedFrom
                  ? entityFrom.name
                    || entityFrom.attribute_abstract
                    || truncate(entityFrom.content, 30)
                    || entityFrom.observable_value
                    || `${fd(entityFrom.first_observed)} - ${fd(
                      entityFrom.last_observed,
                    )}`
                  : t('Restricted')}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                {!restrictedFrom
                  ? t(`entity_${entityFrom.entity_type}`)
                  : t('Restricted')}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity.width }}
              >
                {!restrictedTo
                  ? entityTo.name
                    || entityTo.attribute_abstract
                    || truncate(entityTo.content, 30)
                    || entityTo.observable_value
                    || `${fd(entityTo.first_observed)} - ${fd(
                      entityTo.last_observed,
                    )}`
                  : t('Restricted')}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.first_seen.width }}
              >
                {nsdt(node.first_seen)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.last_seen.width }}
              >
                {nsdt(node.last_seen)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.confidence.width }}
              >
                <ItemConfidence confidence={node.confidence} entityType={node.entity_type} variant="inList" />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.x_opencti_workflow_id.width }}
              >
                <ItemStatus
                  status={node.status}
                  variant="inList"
                  disabled={!node.workflowEnabled}
                />
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
            <StixSightingRelationshipPopover
              stixSightingRelationshipId={node.id}
              paginationOptions={paginationOptions}
            />
          )}
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

StixSightingRelationshipLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  paginationOptions: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
  selectedElements: PropTypes.object,
  deSelectedElements: PropTypes.object,
  selectAll: PropTypes.bool,
  onToggleEntity: PropTypes.func,
  onToggleShiftEntity: PropTypes.func,
};

const StixSightingRelationshipLineFragment = createFragmentContainer(
  StixSightingRelationshipLineComponent,
  {
    node: graphql`
      fragment StixSightingRelationshipLine_node on StixSightingRelationship {
        id
        entity_type
        parent_types
        x_opencti_negative
        attribute_count
        confidence
        first_seen
        last_seen
        description
        status {
          id
          order
          template {
            name
            color
          }
        }
        workflowEnabled
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
            created_at
            updated_at
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
          ... on ObservedData {
            name
            first_observed
            last_observed
          }
          ... on StixCyberObservable {
            id
            entity_type
            parent_types
            created_at
            updated_at
            observable_value
          }
        }
        to {
          ... on StixObject {
            id
            entity_type
            parent_types
            created_at
            updated_at
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
        }
      }
    `,
  },
);

export const StixSightingRelationshipLine = compose(
  inject18n,
  withStyles(styles),
)(StixSightingRelationshipLineFragment);

class StixSightingRelationshipLineDummyComponent extends Component {
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
                style={{ width: dataColumns.x_opencti_negative.width }}
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
                style={{ width: dataColumns.attribute_count.width }}
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
                style={{ width: dataColumns.entity.width }}
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
                style={{ width: dataColumns.first_seen.width }}
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
                style={{ width: dataColumns.last_seen.width }}
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
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.x_opencti_workflow_id.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={80}
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

StixSightingRelationshipLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const StixSightingRelationshipLineDummy = compose(
  inject18n,
  withStyles(styles),
)(StixSightingRelationshipLineDummyComponent);
