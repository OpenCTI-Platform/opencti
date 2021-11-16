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
import { KeyboardArrowRight } from '@material-ui/icons';
import AppleIcon from '@material-ui/icons/Apple';
import { ChessKnight } from 'mdi-material-ui';
import Skeleton from '@material-ui/lab/Skeleton';
import inject18n from '../../../../components/i18n';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import ItemIcon from '../../../../components/ItemIcon';

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

class SoftwareLineComponent extends Component {
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
        to={`/dashboard/assets/software/${node.id}`}
      >
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
                style={{ width: dataColumns.type.width }}
              >
                {/* <AppleIcon /> */}
                {node.asset_type && <ItemIcon type={node.asset_type} />}
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
                style={{ width: dataColumns.vendorName.width }}
              >
                {node.vendor_name && node.vendor_name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.version.width }}
              >
                {/* {fd(node.created)} */}
                {/* Lorem Ipsum Lorem Ipsum */}
                {node.version && node.version}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.patchLevel.width }}
              >
                {node.patch_level && node.patch_level}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.cpeId.width }}
              >
                {/* {fd(node.modified)} */}
                {/* Lorem Ipsum Lorem Ipsum */}
                {node.cpe_identifier && node.cpe_identifier}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.swId.width }}
              >
                {/* {fd(node.modified)} */}
                {/* Lorem Ipsum Lorem Ipsum */}
                {node.software_identifier && node.software_identifier}
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
              </div>
            </div>
          }
        />
        {/* <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ChessKnight />
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
                style={{ width: dataColumns.created.width }}
              >
                {fd(node.created)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.modified.width }}
              >
                {fd(node.modified)}
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
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRight />
        </ListItemIcon> */}
      </ListItem>
    );
  }
}

SoftwareLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  t: PropTypes.func,
  onLabelClick: PropTypes.func,
};

const SoftwareLineFragment = createFragmentContainer(SoftwareLineComponent, {
  node: graphql`
    fragment SoftwareLine_node on SoftwareAsset {
      id
      name
      labels
      asset_type
      asset_id
      vendor_name
      version
      patch_level
      cpe_identifier
      software_identifier
      # created
      # modified
      # objectMarking {
      #   edges {
      #     node {
      #       id
      #       definition
      #     }
      #   }
      # }
      # objectLabel {
      #   edges {
      #     node {
      #       id
      #       value
      #       color
      #     }
      #   }
      # }
    }
  `,
});

export const SoftwareLine = compose(
  inject18n,
  withStyles(styles),
)(SoftwareLineFragment);

class SoftwareDummyComponent extends Component {
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
                style={{ width: dataColumns.vendorName.width }}
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
                style={{ width: dataColumns.version.width }}
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
                style={{ width: dataColumns.patchLevel.width }}
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
                style={{ width: dataColumns.cpeId.width }}
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
                style={{ width: dataColumns.swId.width }}
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

SoftwareDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const SoftwareLineDummy = compose(
  inject18n,
  withStyles(styles),
)(SoftwareDummyComponent);
