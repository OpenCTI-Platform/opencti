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
import inject18n from '../../../../../components/i18n';
import StixCoreObjectLabels from '../../../common/stix_core_objects/StixCoreObjectLabels';
import ItemIcon from '../../../../../components/ItemIcon';

const styles = (theme) => ({
  item: {
    paddingLeft: 38,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    paddingLeft: 24,
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

class RemediationLineComponent extends Component {
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
    const objectLabel = { edges: { node: { id: 1, value: 'labels', color: 'red' } } };
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`/dashboard/risk-assessment/risks/:riskId/remediation/${node.id}`}
      >
        {/* <ListItemIcon classes={{ root: classes.itemIcon }}>
          <PublicOutlined />
        </ListItemIcon> */}
        {/* <ListItemIcon
          classes={{ root: classes.itemIcon }}
          style={{ minWidth: 38 }}
          onClick={onToggleEntity.bind(this, node)}
        >
          <Checkbox
            edge="start"
            color='primary'
            checked={selectAll || node.id in (selectedElements || {})}
            disableRipple={true}
          />
        </ListItemIcon> */}
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {/* KK-HWELL-011 */}
                {node.name && node.name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.type.width }}
              >
                {node.asset_type
                && <ItemIcon type={node.asset_type}/>}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.assetId.width }}
              >
                {/* Lorem Ipsum Lorem Ipsum */}
                {node.asset_id && node.asset_id}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.ipAddress.width }}
              >
                {node.ipv4_address
                  && node.ipv4_address.map((ipv4Address) => (
                    <>
                      <div className="clearfix" />
                      {ipv4Address.ip_address_value && ipv4Address.ip_address_value}
                    </>
                  ))}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.fqdn.width }}
              >
                {/* {fd(node.created)} */}
                {/* Lorem Ipsum Lorem Ipsum */}
                {node.fqdn && node.fqdn}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.os.width }}
              >
                {/* <WindowsIcon /> */}
                {node.installed_operating_system && node.installed_operating_system.name
                && <ItemIcon type={node.installed_operating_system.name}/>}
              </div>
              {/* <div
                className={classes.bodyItem}
                style={{ width: dataColumns.networkId.width }}
              >
                {node.network_id && node.network_id}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectLabel.width }}
              >
                <StixCoreObjectLabels
                  variant="inList"
                  labels={objectLabel}
                  onClick={onLabelClick.bind(this)}
                />
              </div> */}
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

RemediationLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  t: PropTypes.func,
  onLabelClick: PropTypes.func,
};

const RemediationLineFragment = createFragmentContainer(
  RemediationLineComponent,
  {
    node: graphql`
      fragment RemediationLine_node on Risk {
        id
        priority
        deadline
        risk_status
        impacted_control_id
        risk_log {
          edges {
            node {
              related_responses {
                edges {
                  node {
                    lifecycle
                  }
                }
              }
            }
          }
        }
        remediations {
          edges {
            node {
              response_type
            }
          }
        }
      }
    `,
  },
);

export const RemediationLine = compose(
  inject18n,
  withStyles(styles),
)(RemediationLineFragment);

class RemediationLineDummyComponent extends Component {
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
                  variant="circle"
                  width={30}
                  height={30}
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
               <Skeleton animation="wave" variant="circle" width={30} height={30} />
              </div>
              {/* <div
                className={classes.bodyItem}
                style={{ width: dataColumns.networkId.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width={140}
                  height='100%'
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
              </div> */}
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

RemediationLineDummyComponent.propTypes = {
  classes: PropTypes.object,
  dataColumns: PropTypes.object,
};

export const RemediationLineDummy = compose(
  inject18n,
  withStyles(styles),
)(RemediationLineDummyComponent);
