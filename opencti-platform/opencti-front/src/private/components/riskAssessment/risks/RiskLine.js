import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
  pipe,
  map,
  pathOr,
  mergeAll,
} from 'ramda';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import Checkbox from '@material-ui/core/Checkbox';
import ListItemText from '@material-ui/core/ListItemText';
import LayersIcon from '@material-ui/icons/Layers';
import Button from '@material-ui/core/Button';
import WindowsIcon from '@material-ui/icons/LaptopWindows';
import Skeleton from '@material-ui/lab/Skeleton';
import { KeyboardArrowRight, MoreVert, PublicOutlined } from '@material-ui/icons';
import IconButton from '@material-ui/core/IconButton';
import inject18n from '../../../../components/i18n';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import ItemIcon from '../../../../components/ItemIcon';
import RiskAssessmentPopover from './RiskAssessmentPopover';

const styles = (theme) => ({
  item: {
    '&.Mui-selected, &.Mui-selected:hover': {
      backgroundColor: theme.palette.navAlt.background,
    },
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: 36,
    fontSize: 13,
    paddingLeft: 32,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    display: 'flex',
    justifyContent: 'left',
    alignItems: 'center',
  },
  goIcon: {
    minWidth: '0px',
  },
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
  statusButton: {
    cursor: 'default',
    background: '#075AD333',
    marginBottom: '5px',
    border: '1px solid #075AD3',
  },
});

class RiskLineComponent extends Component {
  render() {
    const {
      t,
      fd,
      classes,
      history,
      node,
      selectAll,
      dataColumns,
      onLabelClick,
      onToggleEntity,
      selectedElements,
    } = this.props;
    const riskData = pipe(
      pathOr([], ['related_risks', 'edges']),
      mergeAll,
    )(node);
    const riskRemediation = pipe(
      pathOr([], ['remediations']),
      mergeAll,
    )(riskData.node);
    const riskCharacterization = pipe(
      pathOr([], ['characterizations']),
      mergeAll,
    )(riskData.node);
    console.log('RiskLineNode', node, '----', riskRemediation);
    // const riskCharacterization = pathOr(null, ['node', 'characterizations', 0], riskData);
    // const riskRemediation = pathOr([], ['node', 'remediations', 0], riskData);
    // console.log('RiskLineData', riskCharacterization, riskRemediation);
    const objectLabel = { edges: { node: { id: 1, value: 'labels', color: 'red' } } };

    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        selected={selectAll || node.id in (selectedElements || {})}
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
                style={{ width: dataColumns.poam_id.width }}
              >
                {node.poam_id && node.poam_id}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {node.name && node.name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.risk_level.width }}
              >
                {/* {riskCharacterization.risk && riskCharacterization.risk} */}
                {riskData.node.risk_level && riskData.node.risk_level}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.risk_status.width }}
              >
                <Button
                  variant="outlined"
                  size="small"
                  color="default"
                  className={classes.statusButton}
                >
                  {riskData.node.risk_status && t(riskData.node.risk_status)}
                </Button>
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.risk_response.width }}
              >
                <Button
                  variant="outlined"
                  size="small"
                  color="default"
                  className={classes.statusButton}
                >
                  {riskRemediation.response_type && t(riskRemediation.response_type)}
                </Button>
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.lifecycle.width }}
              >
                <Button
                  variant="outlined"
                  size="small"
                  color="default"
                  className={classes.statusButton}
                >
                  {riskRemediation.lifecycle && t(riskRemediation.lifecycle)}
                </Button>
              </div>
              <div
                className={classes.bodyItem}
                style={{
                  width: dataColumns.occurrences.width,
                  paddingLeft: dataColumns.occurrences.paddingLeft,
                }}
              >
                {node.occurrences && node.occurrences}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.deadline.width }}
              >
                {riskData.node.deadline && t(riskData.node.deadline)}
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
        <ListItemSecondaryAction classes={{ root: classes.goIcon }}>
          <RiskAssessmentPopover history={history} nodeId={node.id}/>
        </ListItemSecondaryAction>
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
      fragment RiskLine_node on POAMItem {
        id
        poam_id
        name
        occurrences
        related_risks {
          edges {
            node {
              __typename
              id
              name
              risk_status
              risk_level
              deadline
              remediations {
                id
                response_type
                lifecycle
              }
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
                style={{ width: dataColumns.poam_id.width }}
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
                style={{ width: dataColumns.risk_level.width }}
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
                style={{ width: dataColumns.risk_status.width }}
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
                style={{ width: dataColumns.risk_response.width }}
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
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width={140}
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.occurrences.width }}
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
