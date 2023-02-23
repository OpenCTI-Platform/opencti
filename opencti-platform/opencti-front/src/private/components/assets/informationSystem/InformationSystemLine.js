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
import CheckIcon from '@material-ui/icons/Check';
import ListItemText from '@material-ui/core/ListItemText';
import Skeleton from '@material-ui/lab/Skeleton';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import CyioCoreObjectLabels from '../../common/stix_core_objects/CyioCoreObjectLabels';
import RiskLevel from '../../common/form/RiskLevel';

const styles = (theme) => ({
  item: {
    '&.Mui-selected, &.Mui-selected:hover': {
      background: theme.palette.dataView.selectedBackgroundColor,
      borderTop: `0.75px solid ${theme.palette.dataView.selectedBorder}`,
      borderBottom: `0.75px solid ${theme.palette.dataView.selectedBorder}`,
    },
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

class InformationSystemLineComponent extends Component {
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
    return (
      <ListItem
         classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        selected={selectAll || node.id in (selectedElements || {})}
        to={`/defender HQ/assets/information_systems/${node.id}`}
        data-cy='software line'
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
                {node.short_name && node.short_name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.risks.width }}
              >
              {node.risk_count && node.risk_count}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.severity.width }}
              >
                {node?.risk_level && <RiskLevel
                  risk={node?.top_risk_severity}
                />}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.critical_system.width }}
              >
                {node.critical_system_designation && <CheckIcon />}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.sensitivity_level.width }}
              >
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.privacy_sensitive.width }}
              >
                {node.privacy_designation && <CheckIcon />}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.status.width }}
              >
                {node.operational_status && node.operational_status}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.label_name.width }}
              >
                {/* <CyioCoreObjectLabels
                  variant="inList"
                  labels={node.labels}
                  onClick={onLabelClick.bind(this)}
                /> */}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.date_created.width }}
              >
                {node.created && node.created}
              </div>
            </div>
          }
        />
      </ListItem>
    );
  }
}

InformationSystemLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  t: PropTypes.func,
  onLabelClick: PropTypes.func,
};

const InformationSystemLineFragment = createFragmentContainer(InformationSystemLineComponent, {
  node: graphql`
    fragment InformationSystemLine_node on InformationSystem {
      id
      short_name
      critical_system_designation
      risk_count
      security_sensitivity_level
      privacy_designation
      operational_status
      created
      top_risk_severity
      labels {
        id
        name
      }
    }
  `,
});

export const InformationSystemLine = compose(
  inject18n,
  withStyles(styles),
)(InformationSystemLineFragment);

class InformationSystemDummyComponent extends Component {
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
                style={{ width: dataColumns.privacy_sensitive.width }}
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
                style={{ width: dataColumns.critical_system.width }}
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
                style={{ width: dataColumns.risks.width }}
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
                style={{ width: dataColumns.severity.width }}
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
                style={{ width: dataColumns.label_name.width }}
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
                style={{ width: dataColumns.date_created.width }}
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
      </ListItem>
    );
  }
}

InformationSystemDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const InformationSystemLineDummy = compose(
  inject18n,
  withStyles(styles),
)(InformationSystemDummyComponent);
