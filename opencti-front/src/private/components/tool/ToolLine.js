import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { KeyboardArrowRight } from '@material-ui/icons';
import { Application } from 'mdi-material-ui';
import { compose } from 'ramda';
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
    width: '50%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  tool_version: {
    float: 'left',
    width: '20%',
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

class ToolLineComponent extends Component {
  render() {
    const { fd, classes, tool } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true} component={Link} to={`/dashboard/catalogs/tools/${tool.id}`}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Application/>
        </ListItemIcon>
        <ListItemText primary={
          <div>
            <div className={classes.bodyItem} style={inlineStyles.name}>
              {tool.name}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.tool_version}>
              {tool.tool_version}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.created}>
              {fd(tool.created)}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.modified}>
              {fd(tool.modified)}
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

ToolLineComponent.propTypes = {
  tool: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const ToolLineFragment = createFragmentContainer(ToolLineComponent, {
  tool: graphql`
      fragment ToolLine_tool on Tool {
          id
          name
          tool_version
          created
          modified
      }
  `,
});

export const ToolLine = compose(
  inject18n,
  withStyles(styles),
)(ToolLineFragment);

class ToolLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Application/>
        </ListItemIcon>
        <ListItemText primary={
          <div>
            <div className={classes.bodyItem} style={inlineStyles.name}>
              <div className='fakeItem' style={{ width: '80%' }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.tool_version}>
              <div className='fakeItem' style={{ width: '70%' }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.created}>
              <div className='fakeItem' style={{ width: 140 }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.modified}>
              <div className='fakeItem' style={{ width: 140 }}/>
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

ToolLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const ToolLineDummy = compose(
  inject18n,
  withStyles(styles),
)(ToolLineDummyComponent);
