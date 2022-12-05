import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
  pipe,
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
import Button from '@material-ui/core/Button';
import Skeleton from '@material-ui/lab/Skeleton';
import inject18n from '../../../../components/i18n';
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
    paddingLeft: 25,
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
      onToggleEntity,
      selectedElements,
    } = this.props;
    const riskData = pipe(
      pathOr([], ['related_risks', 'edges']),
      mergeAll,
    )(node);
    // const riskRemediation = pipe(
    //   pathOr([], ['remediations']),
    //   mergeAll,
    // )(node);
    // const riskCharacterization = pipe(
    //   pathOr([], ['characterizations']),
    //   mergeAll,
    // )(node);
    // const riskCharacterization = pathOr(null, ['node', 'characterizations', 0], riskData);
    // const riskRemediation = pathOr([], ['node', 'remediations', 0], riskData);
    // console.log('RiskLineData', riskCharacterization, riskRemediation);

    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        selected={selectAll || node.id in (selectedElements || {})}
        to={`/activities/risk_assessment/risks/${node?.id}`}
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
                style={{ width: '12.3%' }}
              >
                {node.poam_id && t(node.poam_id)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: '16.3%' }}
              >
                {node.name && t(node.name)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: '6.8%' }}
              >
                {node?.risk_level && node?.risk_level}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: '16.3%' }}
              >
                <Button
                  variant="outlined"
                  size="small"
                  color="default"
                  className={classes.statusButton}
                >
                  {node?.risk_status && t(node?.risk_status)}
                </Button>
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: '11.5%' }}
              >
                <Button
                  variant="outlined"
                  size="small"
                  color="default"
                  className={classes.statusButton}
                >
                  {node?.response_type && t(node.response_type)}
                </Button>
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: '13.5%' }}
              >
                <Button
                  variant="outlined"
                  size="small"
                  color="default"
                  className={classes.statusButton}
                >
                  {node?.lifecycle && t(node.lifecycle)}
                </Button>
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: '10.3%' }}
              >
                {node.occurrences && t(node.occurrences)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: '10%' }}
              >
                {node?.deadline && fd(node?.deadline)}
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
          <RiskAssessmentPopover
            history={history}
            nodeId={node?.id}
            riskNode={riskData.node}
            node={node}
          />
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
      fragment RiskLine_node on Risk {
        id
        poam_id
        name
        risk_level
        risk_status
        response_type
        lifecycle
        occurrences
        deadline
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
                style={{ width: dataColumns.response_type.width }}
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
