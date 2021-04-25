import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { MoreVertOutlined, HelpOutlined } from '@material-ui/icons';
import Chip from '@material-ui/core/Chip';
import { Link } from 'react-router-dom';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ItemConfidence from '../../../../components/ItemConfidence';
import StixSightingRelationshipPopover from './StixSightingRelationshipPopover';
import { resolveLink } from '../../../../utils/Entity';
import { truncate } from '../../../../utils/String';

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
      nsd,
      t,
      fd,
      classes,
      dataColumns,
      node,
      paginationOptions,
    } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`${resolveLink(node.from.entity_type)}/${node.from.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ItemIcon type={node.from.entity_type} />
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
                      : t('Malicious')
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
                {node.from.name
                  || node.from.attribute_abstract
                  || truncate(node.from.content, 30)
                  || node.from.observable_value
                  || `${fd(node.from.first_observed)} - ${fd(
                    node.from.last_observed,
                  )}`}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                {t(`entity_${node.from.entity_type}`)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.first_seen.width }}
              >
                {nsd(node.first_seen)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.last_seen.width }}
              >
                {nsd(node.last_seen)}
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
          <StixSightingRelationshipPopover
            stixSightingRelationshipId={node.id}
            paginationOptions={paginationOptions}
          />
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
  nsd: PropTypes.func,
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
          ... on ObservedData {
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
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.attribute_count.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                <div className="fakeItem" style={{ width: '70%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.first_seen.width }}
              >
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.last_seen.width }}
              >
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.confidence.width }}
              >
                <div className="fakeItem" style={{ width: 100 }} />
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
