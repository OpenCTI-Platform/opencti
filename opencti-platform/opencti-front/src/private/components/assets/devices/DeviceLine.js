/* eslint-disable */
/* refactor */
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
import Skeleton from '@material-ui/lab/Skeleton';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import CyioCoreObjectLabels from '../../common/stix_core_objects/CyioCoreObjectLabels';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
    borderTop: `0.75px solid ${theme.palette.dataView.border}`,
    borderBottom: `0.75px solid ${theme.palette.dataView.border}`,
  },
  selectedItem: {
    paddingLeft: 10,
    height: 50,
    borderTop: `0.75px solid ${theme.palette.dataView.selectedBorder}`,
    borderBottom: `0.75px solid ${theme.palette.dataView.selectedBorder}`,
    background: theme.palette.dataView.selectedBackgroundColor,
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

class DeviceLineComponent extends Component {
  render() {
    const {
      classes,
      node,
      selectAll,
      dataColumns,
      onLabelClick,
      onToggleEntity,
      selectedElements,
    } = this.props;
    const operatingSystem = node.installed_operating_system?.vendor_name?.toLowerCase();
    return (
      <ListItem
        classes={{
          root: (selectAll || node.id in (selectedElements || {}))
            ? classes.selectedItem : classes.item,
        }}
        divider={true}
        button={true}
        component={Link}
        selected={selectAll || node.id in (selectedElements || {})}
        to={`/defender HQ/assets/devices/${node.id}`}
        data-cy='device line'
      >
        {/* <ListItemIcon classes={{ root: classes.itemIcon }}>
          <PublicOutlined />
        </ListItemIcon> */}
        <ListItemIcon
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
        </ListItemIcon>
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
                style={{ width: dataColumns.asset_type.width }}
              >
                {node.asset_type
                  && <ItemIcon type={node.asset_type} />}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.asset_id.width }}
              >
                {node.asset_id && node.asset_id}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.ip_address_value.width }}
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
                {node.fqdn && node.fqdn}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.installed_os_name.width }}
              >
                {node.installed_operating_system?.name &&
                  node.installed_operating_system?.vendor_name &&
                  <ItemIcon variant='inline' type={operatingSystem === 'microsoft' || operatingSystem === 'apple' || operatingSystem === 'linux' ? operatingSystem : 'other'} />}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.network_id.width }}
              >
                {node.network_id && node.network_id}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.label_name.width }}
              >
                <CyioCoreObjectLabels
                  variant="inList"
                  labels={node.labels}
                  onClick={onLabelClick.bind(this)}
                />
                {/* <StixCoreObjectLabels
                  variant="inList"
                  labels={objectLabel}
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
      fragment DeviceLine_node on HardwareAsset {
        id
        name
        asset_id
        asset_type
        ipv4_address{
          ip_address_value
        }
        installed_operating_system{
          name
          vendor_name
        }
        fqdn
        network_id
        # objectLabel {
        #   edges {
        #     node {
        #       id
        #       value
        #       color
        #     }
        #   }
        # }
        labels {
          __typename
          id
          name
          color
          entity_type
          description
        }
        external_references {
          __typename
          id
          source_name
          description
          entity_type
          url
          hashes {
            value
          }
          external_id
        }
        notes {
          __typename
          id
          # created
          # modified
          entity_type
          abstract
          content
          authors
        }
        # objectMarking {
        #   edges {
        #     node {
        #       id
        #       definition
        #     }
        #   }
        # }
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
                style={{ width: dataColumns.asset_type.width }}
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
                style={{ width: dataColumns.asset_id.width }}
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
                style={{ width: dataColumns.ip_address_value.width }}
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
                style={{ width: dataColumns.installed_os_name.width }}
              >
                <Skeleton animation="wave" variant="circle" width={30} height={30} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.network_id.width }}
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
                style={{ width: dataColumns.label_name.width }}
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
        {/* <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRight />
        </ListItemIcon> */}
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
