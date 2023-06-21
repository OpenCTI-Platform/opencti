import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVertOutlined, HelpOutlined } from '@mui/icons-material';
import Chip from '@mui/material/Chip';
import { Link } from 'react-router-dom';
import Skeleton from '@mui/material/Skeleton';
import Tooltip from '@mui/material/Tooltip';
import * as R from 'ramda';
import { AutoFix } from 'mdi-material-ui';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ItemConfidence from '../../../../components/ItemConfidence';
import StixSightingRelationshipPopover from './StixSightingRelationshipPopover';
import { resolveLink } from '../../../../utils/Entity';

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

class EntityStixSightingRelationshipLineComponent extends Component {
  render() {
    const { nsdt, t, classes, dataColumns, node, paginationOptions, isTo } = this.props;
    const entity = isTo ? node.from : node.to;
    const restricted = entity === null;
    const entityLink = entity ? `${resolveLink(entity.entity_type)}/${entity.id}` : undefined;
    const link = `${entityLink}/knowledge/sightings/${node.id}`;
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
          <ItemIcon type={!restricted ? entity.entity_type : 'restricted'} />
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
                style={{ width: dataColumns.attribute_count.width }}
              >
                {node.attribute_count}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {!restricted
                  ? entity.name || entity.observable_value
                  : t('Restricted')}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                {!restricted
                  ? t(`entity_${entity.entity_type}`)
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
              disabled={restricted}
            />
          )}
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

EntityStixSightingRelationshipLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  paginationOptions: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
  isTo: PropTypes.bool,
  entityLink: PropTypes.string,
};

const EntityStixSightingRelationshipLineFragment = createFragmentContainer(
  EntityStixSightingRelationshipLineComponent,
  {
    node: graphql`
      fragment EntityStixSightingRelationshipLine_node on StixSightingRelationship {
        id
        entity_type
        parent_types
        x_opencti_negative
        attribute_count
        confidence
        first_seen
        last_seen
        description
        is_inferred
        x_opencti_inferences {
          rule {
            id
            name
          }
        }
        from {
          ... on StixObject {
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
          ... on ThreatActorGroup {
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

export const EntityStixSightingRelationshipLine = compose(
  inject18n,
  withStyles(styles),
)(EntityStixSightingRelationshipLineFragment);

class EntityStixSightingRelationshipLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <HelpOutlined />
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

EntityStixSightingRelationshipLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const EntityStixSightingRelationshipLineDummy = compose(
  inject18n,
  withStyles(styles),
)(EntityStixSightingRelationshipLineDummyComponent);
