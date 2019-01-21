import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { MoreVert } from '@material-ui/icons';
import { LockPattern } from 'mdi-material-ui';
import { compose } from 'ramda';
import inject18n from '../../../components/i18n';
import KillChainPhasePopover from './KillChainPhasePopover';

const styles = theme => ({
  item: {
    paddingLeft: 10,
    transition: 'background-color 0.1s ease',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    fontSize: 13,
  },
  goIcon: {
    position: 'absolute',
    right: 10,
    marginRight: 0,
  },
  itemIconDisabled: {
    color: theme.palette.text.disabled,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.text.disabled,
  },
});

const inlineStyles = {
  kill_chain_name: {
    float: 'left',
    width: '30%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  phase_name: {
    float: 'left',
    width: '35%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  phase_order: {
    float: 'left',
    width: '10%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  created: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

class KillChainPhaseLineComponent extends Component {
  render() {
    const {
      fd, classes, killChainPhase, paginationOptions,
    } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <LockPattern/>
        </ListItemIcon>
        <ListItemText primary={
          <div>
            <div className={classes.bodyItem} style={inlineStyles.kill_chain_name}>
              {killChainPhase.kill_chain_name}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.phase_name}>
              {killChainPhase.phase_name}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.phase_order}>
              {killChainPhase.phase_order}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.created}>
              {fd(killChainPhase.created)}
            </div>
          </div>
        }/>
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KillChainPhasePopover
            killChainPhaseId={killChainPhase.id}
            paginationOptions={paginationOptions}
          />
        </ListItemIcon>
      </ListItem>
    );
  }
}

KillChainPhaseLineComponent.propTypes = {
  killChainPhase: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const KillChainPhaseLineFragment = createFragmentContainer(KillChainPhaseLineComponent, {
  killChainPhase: graphql`
      fragment KillChainPhaseLine_killChainPhase on KillChainPhase {
          id
          kill_chain_name
          phase_name
          phase_order
          created
          modified
      }
  `,
});

export const KillChainPhaseLine = compose(
  inject18n,
  withStyles(styles),
)(KillChainPhaseLineFragment);

class KillChainPhaseLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <LockPattern/>
        </ListItemIcon>
        <ListItemText primary={
          <div>
            <div className={classes.bodyItem} style={inlineStyles.kill_chain_name}>
              <div className={classes.placeholder} style={{ width: '80%' }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.phase_name}>
              <div className={classes.placeholder} style={{ width: '70%' }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.phase_order}>
              <div className={classes.placeholder} style={{ width: '90%' }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.created}>
              <div className={classes.placeholder} style={{ width: 140 }}/>
            </div>
          </div>
        }/>
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <MoreVert/>
        </ListItemIcon>
      </ListItem>
    );
  }
}

KillChainPhaseLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const KillChainPhaseLineDummy = compose(
  inject18n,
  withStyles(styles),
)(KillChainPhaseLineDummyComponent);
