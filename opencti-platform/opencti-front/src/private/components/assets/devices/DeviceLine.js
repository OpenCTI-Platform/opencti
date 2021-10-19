import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import Checkbox from '@material-ui/core/Checkbox';
import ListItemText from '@material-ui/core/ListItemText';
import DeviceIcon from '@material-ui/icons/Devices';
import WindowsIcon from '@material-ui/icons/LaptopWindows';
import Skeleton from '@material-ui/lab/Skeleton';
import { KeyboardArrowRight, PublicOutlined } from '@material-ui/icons';
import inject18n from '../../../../components/i18n';
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

class DeviceLineComponent extends Component {
  render() {
    const {
      fd,
      classes,
      node,
      selectAll,
      dataColumns,
      onLabelClick,
      onToggleEntity,
      selectedElements,
    } = this.props;
    console.log('DarkLightnodeLineDevices', node);
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`/dashboard/assets/devices/${node.id}`}
      >
        {/* <ListItemIcon classes={{ root: classes.itemIcon }}>
          <PublicOutlined />
        </ListItemIcon> */}
        <ListItemIcon
          classes={{ root: classes.itemIcon }}
          style={{ minWidth: 50 }}
          onClick={onToggleEntity.bind(this, node)}
        >
          <Checkbox
            edge="start"
            checked={selectAll || node.id in (selectedElements || {})}
            disableRipple={true}
          />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {/* KK-HWELL-011 */}
                {node.name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.type.width }}
              >
                <DeviceIcon />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.assetId.width }}
              >
                {/* Lorem Ipsum Lorem Ipsum */}
                {node.asset_id}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.ipAddress.width }}
              >
                192.168.43.201
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.fqdn.width }}
              >
                {/* {fd(node.created)} */}
                {/* Lorem Ipsum Lorem Ipsum */}
                {node.fqdn}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.os.width }}
              >
                <WindowsIcon />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.networkId.width }}
              >
                {/* {fd(node.modified)} */}
                {/* Lorem Ipsum Lorem Ipsum */}
                {node.network_id}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectLabel.width }}
              >
                {/* <StixCoreObjectLabels
                  variant="inList"
                  labels={node.objectLabel}
                  onClick={onLabelClick.bind(this)}
                /> */}
              </div>
            </div>
          }
        />
        {/* <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRight />
        </ListItemIcon> */}
      </ListItem>
    );
  }
}

DeviceLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  t: PropTypes.func,
  onLabelClick: PropTypes.func,
};

const DeviceLineFragment = createFragmentContainer(
  DeviceLineComponent,
  {
    node: graphql`
      fragment DeviceLine_node on ThreatActor {
        id
        name
        created
        modified
        objectLabel {
          edges {
            node {
              id
              value
              color
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
      }
    `,
  },
);

export const DeviceLine = compose(
  inject18n,
  withStyles(styles),
)(DeviceLineFragment);

class DeviceLineDummyComponent extends Component {
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
                style={{ width: dataColumns.name.width }}
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
                style={{ width: dataColumns.type.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width={140}
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.assetId.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width={140}
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.ipAddress.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width={140}
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.fqdn.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width={140}
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.os.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width={140}
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.networkId.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width={140}
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
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRight />
        </ListItemIcon>
      </ListItem>
    );
  }
}

DeviceLineDummyComponent.propTypes = {
  classes: PropTypes.object,
  dataColumns: PropTypes.object,
};

export const DeviceLineDummy = compose(
  inject18n,
  withStyles(styles),
)(DeviceLineDummyComponent);
