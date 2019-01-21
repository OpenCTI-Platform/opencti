import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { KeyboardArrowRight } from '@material-ui/icons';
import { Diamond } from 'mdi-material-ui';
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

class IntrusionSetLineComponent extends Component {
  render() {
    const { fd, classes, intrusionSet } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true} component={Link} to={`/dashboard/knowledge/intrusion_sets/${intrusionSet.id}`}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Diamond/>
        </ListItemIcon>
        <ListItemText primary={
          <div>
            <div className={classes.bodyItem} style={inlineStyles.name}>
                {intrusionSet.name}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.created}>
                {fd(intrusionSet.created)}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.modified}>
                {fd(intrusionSet.modified)}
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

IntrusionSetLineComponent.propTypes = {
  intrusionSet: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const IntrusionSetLineFragment = createFragmentContainer(IntrusionSetLineComponent, {
  intrusionSet: graphql`
        fragment IntrusionSetLine_intrusionSet on IntrusionSet {
            id
            name
            created
            modified
        }
    `,
});

export const IntrusionSetLine = compose(
  inject18n,
  withStyles(styles),
)(IntrusionSetLineFragment);

class IntrusionSetLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Diamond/>
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

IntrusionSetLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const IntrusionSetLineDummy = compose(
  inject18n,
  withStyles(styles),
)(IntrusionSetLineDummyComponent);
