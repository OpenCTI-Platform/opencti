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
import LayersIcon from '@material-ui/icons/Layers';
import Button from '@material-ui/core/Button';
import WindowsIcon from '@material-ui/icons/LaptopWindows';
import Skeleton from '@material-ui/lab/Skeleton';
import { KeyboardArrowRight, PublicOutlined } from '@material-ui/icons';
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
    height: 30,
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

class RiskLineComponent extends Component {
  render() {
    const {
      t,
      fd,
      classes,
      node,
      selectAll,
      dataColumns,
      onLabelClick,
      onToggleEntity,
      selectedElements,
    } = this.props;
    console.log('node', node);
    const objectLabel = { edges: { node: { id: 1, value: 'labels', color: 'red' } } };
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`/dashboard/risk-assessment/risks/${node.id}`}
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
                style={{ width: dataColumns.id.width }}
              >
                {/* KK-HWELL-011 */}
                {node.id && node.id}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.priority.width }}
              >
                {node.priority && node.priority}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.risk.width }}
              >
                Medium
                {/* {node.asset_id && node.asset_id} */}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.status.width }}
              >
                <Button
                  variant="outlined"
                  size="small"
                  style={{ cursor: 'default' }}
                >
                  {node.risk_status && t(node.risk_status)}
                </Button>
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.response.width }}
              >
                Avoid
                {node.fqdn && node.fqdn}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.lifecycle.width }}
              >
                Lorem
                {/* {node.lifecycle && node.lifecycle} */}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.component.width }}
              >
                Lorem
                {/* {node.fqdn && node.fqdn} */}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.asset.width }}
              >
                <LayersIcon /> Lorem
                {/* {node.network_id && node.network_id} */}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.deadline.width }}
              >
                {/* {fd(node.modified)} */}
                {/* Lorem Ipsum Lorem Ipsum */}
                {node.deadline && fd(node.deadline)}
              </div>
              {/* <div
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

RiskLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  t: PropTypes.func,
  onLabelClick: PropTypes.func,
};

const RiskLineFragment = createFragmentContainer(
  RiskLineComponent,
  {
    node: graphql`
      fragment RiskLine_node on Risk {
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

export const RiskLine = compose(
  inject18n,
  withStyles(styles),
)(RiskLineFragment);

class RiskLineDummyComponent extends Component {
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
                style={{ width: dataColumns.id.width }}
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
                style={{ width: dataColumns.priority.width }}
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
                style={{ width: dataColumns.risk.width }}
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
                style={{ width: dataColumns.status.width }}
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
                style={{ width: dataColumns.response.width }}
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
                style={{ width: dataColumns.lifecycle.width }}
              >
               <Skeleton animation="wave" variant="circle" width={30} height={30} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.component.width }}
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
                style={{ width: dataColumns.asset.width }}
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
                style={{ width: dataColumns.deadline.width }}
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

RiskLineDummyComponent.propTypes = {
  classes: PropTypes.object,
  dataColumns: PropTypes.object,
};

export const RiskLineDummy = compose(
  inject18n,
  withStyles(styles),
)(RiskLineDummyComponent);
