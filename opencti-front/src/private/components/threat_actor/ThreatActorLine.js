import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { compose, propOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { KeyboardArrowRight, Public } from '@material-ui/icons';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  item: {
    paddingLeft: 10,
    transition: 'background-color 0.1s ease',
    cursor: 'pointer',
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
  name: {
    float: 'left',
    width: '70%',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  created: {
    float: 'left',
    width: '15%',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  modified: {
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

class ThreatActorLineComponent extends Component {
  render() {
    const { fd, classes, threatActor } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true} component={Link} to={`/dashboard/knowledge/threat_actors/${threatActor.id}`}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Public/>
        </ListItemIcon>
        <ListItemText primary={
          <div>
            <div className={classes.bodyItem} style={inlineStyles.name}>
                {propOr('-', 'name', threatActor)}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.created}>
                {fd(propOr(null, 'created', threatActor))}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.modified}>
                {fd(propOr(null, 'modified', threatActor))}
            </div>
          </div>
        }/>
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRight/>
        </ListItemIcon>
      </ListItem>
    );
  }
}

ThreatActorLineComponent.propTypes = {
  threatActor: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const ThreatActorLineFragment = createFragmentContainer(ThreatActorLineComponent, {
  threatActor: graphql`
        fragment ThreatActorLine_threatActor on ThreatActor {
            id,
            name,
            created,
            modified
        }
    `,
});

export const ThreatActorLine = compose(
  inject18n,
  withStyles(styles),
)(ThreatActorLineFragment);

class ThreatActorLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Public/>
        </ListItemIcon>
        <ListItemText primary={
          <div>
            <div className={classes.bodyItem} style={inlineStyles.name}>
                <div className={classes.placeholder} style={{ width: '80%' }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.created}>
                <div className={classes.placeholder} style={{ width: 140 }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.modified}>
                <div className={classes.placeholder} style={{ width: 140 }}/>
            </div>
          </div>
        }/>
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRight/>
        </ListItemIcon>
      </ListItem>
    );
  }
}

ThreatActorLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const ThreatActorLineDummy = compose(
  inject18n,
  withStyles(styles),
)(ThreatActorLineDummyComponent);
