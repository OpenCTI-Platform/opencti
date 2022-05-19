import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { graphql, createFragmentContainer } from 'react-relay';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import {
  KeyboardArrowRightOutlined,
  WifiTetheringOutlined,
} from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import inject18n from '../../../../components/i18n';
import ItemMarking from '../../../../components/ItemMarking';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';

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
    const { nsdt, classes, node, dataColumns, onLabelClick, n } = this.props;
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
                style={{ width: dataColumns.name.width }}
              >
                {node.name}
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
        name
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
                style={{ width: dataColumns.number_observed.width }}
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
                style={{ width: dataColumns.first_observed.width }}
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
                style={{ width: dataColumns.last_observed.width }}
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
                style={{ width: dataColumns.objectLabel.width }}
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
