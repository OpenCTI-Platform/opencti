import React, { Component } from 'react';
import PropTypes from 'prop-types';
import {
  compose, pipe, pathOr, join, map, sort,
} from 'ramda';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { KeyboardArrowRight } from '@material-ui/icons';
import { LockPattern } from 'mdi-material-ui';
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
});

const inlineStyles = {
  killChainPhases: {
    float: 'left',
    width: '25%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  name: {
    float: 'left',
    width: '45%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  created: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  modified: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

class AttackPatternLineComponent extends Component {
  render() {
    const {
      fd, classes, attackPattern, orderAsc,
    } = this.props;
    const killchainPhases = pipe(
      pathOr([], ['killChainPhases', 'edges']),
      map(n => n.node.phase_name),
      sort((a, b) => (orderAsc ? a.localeCompare(b) : b.localeCompare(a))),
      join(', '),
    )(attackPattern);
    return (
      <ListItem
        classes={{ default: classes.item }}
        divider={true}
        component={Link}
        to={`/dashboard/catalogs/attack_patterns/${attackPattern.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <LockPattern />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={inlineStyles.killChainPhases}
              >
                {killchainPhases}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.name}>
                {attackPattern.name}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.created}>
                {fd(attackPattern.created)}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.modified}>
                {fd(attackPattern.modified)}
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

AttackPatternLineComponent.propTypes = {
  attackPattern: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  orderAsc: PropTypes.bool,
};

const AttackPatternLineFragment = createFragmentContainer(
  AttackPatternLineComponent,
  {
    attackPattern: graphql`
      fragment AttackPatternLine_attackPattern on AttackPattern {
        id
        name
        created
        modified
        killChainPhases {
          edges {
            node {
              id
              kill_chain_name
              phase_name
            }
          }
        }
      }
    `,
  },
);

export const AttackPatternLine = compose(
  inject18n,
  withStyles(styles),
)(AttackPatternLineFragment);

class AttackPatternLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <LockPattern />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={inlineStyles.killChainPhases}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.name}>
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.created}>
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.modified}>
                <div className="fakeItem" style={{ width: 140 }} />
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

AttackPatternLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const AttackPatternLineDummy = compose(
  inject18n,
  withStyles(styles),
)(AttackPatternLineDummyComponent);
