import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVert } from '@mui/icons-material';
import { Launch } from 'mdi-material-ui';
import { compose } from 'ramda';
import Skeleton from '@mui/material/Skeleton';
import inject18n from '../../../../components/i18n';
import KillChainPhasePopover from './KillChainPhasePopover';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
    cursor: 'default',
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

class KillChainPhaseLineComponent extends Component {
  render() {
    const { fd, classes, node, dataColumns, paginationOptions } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true} button={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Launch />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.kill_chain_name.width }}
              >
                {node.kill_chain_name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.phase_name.width }}
              >
                {node.phase_name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.x_opencti_order.width }}
              >
                {node.x_opencti_order}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created.width }}
              >
                {fd(node.created)}
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <KillChainPhasePopover
            killChainPhaseId={node.id}
            paginationOptions={paginationOptions}
          />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

KillChainPhaseLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const KillChainPhaseLineFragment = createFragmentContainer(
  KillChainPhaseLineComponent,
  {
    node: graphql`
      fragment KillChainPhaseLine_node on KillChainPhase {
        id
        kill_chain_name
        phase_name
        x_opencti_order
        created
        modified
      }
    `,
  },
);

export const KillChainPhaseLine = compose(
  inject18n,
  withStyles(styles),
)(KillChainPhaseLineFragment);

class KillChainPhaseLineDummyComponent extends Component {
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
                style={{ width: dataColumns.kill_chain_name.width }}
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
                style={{ width: dataColumns.phase_name.width }}
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
                style={{ width: dataColumns.x_opencti_order.width }}
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
                style={{ width: dataColumns.created.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={140}
                  height="100%"
                />
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
          <MoreVert />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

KillChainPhaseLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const KillChainPhaseLineDummy = compose(
  inject18n,
  withStyles(styles),
)(KillChainPhaseLineDummyComponent);
