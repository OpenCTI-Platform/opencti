import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Link } from 'react-router-dom';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { MoreVert } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { ListItemButton } from '@mui/material';
import Box from '@mui/material/Box';
import inject18n from '../../../../components/i18n';
import ItemConfidence from '../../../../components/ItemConfidence';
import StixCoreRelationshipPopover from '../../common/stix_core_relationships/StixCoreRelationshipPopover';
import ItemIcon from '../../../../components/ItemIcon';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import ItemEntityType from '../../../../components/ItemEntityType';
import { isEmptyField } from '../../../../utils/utils';

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

class IndicatorEntityLineComponent extends Component {
  render() {
    const {
      fsd,
      t,
      classes,
      dataColumns,
      node,
      paginationOptions,
      displayRelation,
      entityId,
      entityLink,
    } = this.props;
    const element = node.to?.id === entityId ? node.from : node.to;
    const restricted = isEmptyField(element);
    const link = `${entityLink}/relations/${node.id}`;
    return (
      <ListItem
        divider={true}
        disablePadding
        secondaryAction={(
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <StixCoreRelationshipPopover
              stixCoreRelationshipId={node.id}
              paginationOptions={paginationOptions}
              disabled={restricted}
            />
          </Security>
        )}
      >
        <ListItemButton
          classes={{ root: classes.item }}
          component={Link}
          to={link}
          disabled={restricted}
        >
          <ListItemIcon classes={{ root: classes.itemIcon }}>
            <ItemIcon type={node.entity_type} />
          </ListItemIcon>
          <ListItemText
            primary={(
              <div>
                {displayRelation && (
                  <div
                    className={classes.bodyItem}
                    style={{ width: dataColumns.relationship_type.width }}
                  >
                    <ItemEntityType
                      entityType={node.relationship_type}
                    />
                  </div>
                )}
                <div
                  className={classes.bodyItem}
                  style={{ width: dataColumns.entity_type.width }}
                >
                  <ItemEntityType
                    entityType={element.entity_type === 'stix_relation'
                      || element.entity_type === 'stix-relation'
                      ? element.parent_types[0]
                      : element.entity_type}
                    isRestricted={restricted}
                    size="large"
                    showIcon
                  />
                </div>
                <div
                  className={classes.bodyItem}
                  style={{ width: dataColumns.name.width }}
                >
                  { }
                  {!restricted
                    ? element.entity_type === 'stix_relation'
                    || element.entity_type === 'stix-relation'
                      ? `${element.from.name} ${String.fromCharCode(8594)} ${
                        element.to.name || element.to.observable_value
                      }`
                      : element.name || element.observable_value
                    : t('Restricted')}
                </div>
                <div
                  className={classes.bodyItem}
                  style={{ width: dataColumns.createdBy.width }}
                >
                  {node.createdBy?.name ?? '-'}
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
                  style={{ width: dataColumns.confidence.width }}
                >
                  <ItemConfidence confidence={node.confidence} entityType="stix-core-relationship" variant="inList" />
                </div>
              </div>
            )}
          />
        </ListItemButton>
      </ListItem>
    );
  }
}

IndicatorEntityLineComponent.propTypes = {
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
  displayRelation: PropTypes.bool,
  entityId: PropTypes.string,
};

const IndicatorEntityLineFragment = createFragmentContainer(
  IndicatorEntityLineComponent,
  {
    node: graphql`
      fragment IndicatorEntityLine_node on StixCoreRelationship {
        id
        entity_type
        relationship_type
        confidence
        start_time
        stop_time
        description
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
        objectLabel {
          id
          value
          color
        }
        creators {
          id
          name
        }
        from {
          ... on BasicObject {
            id
            entity_type
            parent_types
          }
          ... on BasicRelationship {
            id
            entity_type
            parent_types
          }
          ... on StixCoreObject {
            created_at
            updated_at
          }
          ... on StixCoreRelationship {
            created_at
            updated_at
          }
          ... on AttackPattern {
            name
            description
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
          ... on StixCyberObservable {
            observable_value
          }
          ... on StixCoreRelationship {
            from {
              ... on AttackPattern {
                name
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
              ... on StixCyberObservable {
                observable_value
              }
            }
            to {
              ... on AttackPattern {
                name
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
              ... on StixCyberObservable {
                observable_value
              }
            }
          }
        }
        to {
          ... on BasicObject {
            id
            entity_type
            parent_types
          }
          ... on BasicRelationship {
            id
            entity_type
            parent_types
          }
          ... on StixCoreObject {
            created_at
            updated_at
          }
          ... on StixCoreRelationship {
            created_at
            updated_at
          }
          ... on AttackPattern {
            name
            description
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
          ... on StixCyberObservable {
            observable_value
          }
          ... on StixCoreRelationship {
            from {
              ... on AttackPattern {
                name
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
              ... on StixCyberObservable {
                observable_value
              }
            }
            to {
              ... on AttackPattern {
                name
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
              ... on StixCyberObservable {
                observable_value
              }
            }
          }
        }
      }
    `,
  },
);

export const IndicatorEntityLine = compose(
  inject18n,
  withStyles(styles),
)(IndicatorEntityLineFragment);

class IndicatorEntityLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns, displayRelation } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        secondaryAction={(
          <Box sx={{ root: classes.itemIconDisabled }}>
            <MoreVert />
          </Box>
        )}
      >
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Skeleton
            animation="wave"
            variant="circular"
            width={30}
            height={30}
          />
        </ListItemIcon>
        <ListItemText
          primary={(
            <div>
              {displayRelation && (
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
              )}
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
                style={{ width: dataColumns.start_time.width }}
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
                style={{ width: dataColumns.stop_time.width }}
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
          )}
        />
      </ListItem>
    );
  }
}

IndicatorEntityLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
  displayRelation: PropTypes.bool,
};

export const IndicatorEntityLineDummy = compose(
  inject18n,
  withStyles(styles),
)(IndicatorEntityLineDummyComponent);
