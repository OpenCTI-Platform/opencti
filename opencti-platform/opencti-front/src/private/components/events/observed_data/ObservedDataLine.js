import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import {
  KeyboardArrowRightOutlined,
  WifiTetheringOutlined,
} from '@material-ui/icons';
import Skeleton from '@material-ui/lab/Skeleton';
import inject18n from '../../../../components/i18n';
import ItemMarking from '../../../../components/ItemMarking';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import { defaultValue } from '../../../../utils/Graph';

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
  },
  goIcon: {
    position: 'absolute',
    right: -10,
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

class ObservedDataLineComponent extends Component {
  render() {
    const {
      t, nsdt, classes, node, dataColumns, onLabelClick, n,
    } = this.props;
    const firstEntity = node.objects.edges.length > 0 ? R.head(node.objects.edges).node : null;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`/dashboard/events/observed_data/${node.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <WifiTetheringOutlined />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.first_entity.width }}
              >
                {firstEntity ? defaultValue(firstEntity) : t('None')}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.number_observed.width }}
              >
                {n(node.number_observed)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.first_observed.width }}
              >
                {nsdt(node.first_observed)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.last_observed.width }}
              >
                {nsdt(node.last_observed)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.createdBy.width }}
              >
                {R.pathOr('', ['createdBy', 'name'], node)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectLabel.width }}
              >
                <StixCoreObjectLabels
                  variant="inList"
                  labels={node.objectLabel}
                  onClick={onLabelClick.bind(this)}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectMarking.width }}
              >
                {R.take(1, R.pathOr([], ['objectMarking', 'edges'], node)).map(
                  (markingDefinition) => (
                    <ItemMarking
                      key={markingDefinition.node.id}
                      variant="inList"
                      label={markingDefinition.node.definition}
                      color={markingDefinition.node.x_opencti_color}
                    />
                  ),
                )}
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRightOutlined />
        </ListItemIcon>
      </ListItem>
    );
  }
}

ObservedDataLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  onLabelClick: PropTypes.func,
};

const ObservedDataLineFragment = createFragmentContainer(
  ObservedDataLineComponent,
  {
    node: graphql`
      fragment ObservedDataLine_node on ObservedData {
        id
        created
        first_observed
        last_observed
        number_observed
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        objectMarking {
          edges {
            node {
              id
              definition
              x_opencti_color
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
        objects(first: 1) {
          edges {
            node {
              ... on StixCoreObject {
                id
                entity_type
                parent_types
                created_at
                createdBy {
                  ... on Identity {
                    id
                    name
                    entity_type
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
              }
              ... on AttackPattern {
                name
                description
                x_mitre_id
              }
              ... on Campaign {
                name
                description
                first_seen
                last_seen
              }
              ... on Note {
                attribute_abstract
              }
              ... on ObservedData {
                first_observed
                last_observed
              }
              ... on Opinion {
                opinion
              }
              ... on Report {
                name
                description
                published
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
                valid_from
              }
              ... on Infrastructure {
                name
                description
              }
              ... on IntrusionSet {
                name
                description
                first_seen
                last_seen
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
                first_seen
                last_seen
              }
              ... on ThreatActor {
                name
                description
                first_seen
                last_seen
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
                first_seen
                last_seen
              }
              ... on StixCyberObservable {
                observable_value
                x_opencti_description
              }
            }
          }
        }
      }
    `,
  },
);

export const ObservedDataLine = R.compose(
  inject18n,
  withStyles(styles),
)(ObservedDataLineFragment);

class ObservedDataLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Skeleton animation="wave" variant="circle" width={30} height={30} />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.first_entity.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.number_observed.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.first_observed.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.last_observed.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
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
                  variant="rect"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectLabel.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectMarking.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width={100}
                  height="100%"
                />
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRightOutlined />
        </ListItemIcon>
      </ListItem>
    );
  }
}

ObservedDataLineDummyComponent.propTypes = {
  classes: PropTypes.object,
  dataColumns: PropTypes.object,
};

export const ObservedDataLineDummy = R.compose(
  inject18n,
  withStyles(styles),
)(ObservedDataLineDummyComponent);
