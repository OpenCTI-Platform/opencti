import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { KeyboardArrowRight, Work } from '@material-ui/icons';
import { compose, pathOr, take } from 'ramda';
import inject18n from '../../../components/i18n';
import ItemMarking from '../../../components/ItemMarking';

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
    height: '100%',
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
    width: '45%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  owner: {
    float: 'left',
    width: '25%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  created_at: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  marking: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

class WorkspaceLineComponent extends Component {
  render() {
    const { fd, classes, workspace } = this.props;

    return (
      <ListItem classes={{ root: classes.item }} divider={true} component={Link} to={`/dashboard/investigate/${workspace.id}`}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Work/>
        </ListItemIcon>
        <ListItemText primary={
          <div>
            <div className={classes.bodyItem} style={inlineStyles.name}>
              {workspace.name}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.owner}>
              {pathOr('', ['ownedBy', 'node', 'name'], workspace)}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.created_at}>
              {fd(workspace.created_at)}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.marking}>
              {take(1, pathOr([], ['markingDefinitions', 'edges'], workspace)).map(markingDefinition => <ItemMarking key={markingDefinition.node.id} variant='inList' label={markingDefinition.node.definition}/>)}
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

WorkspaceLineComponent.propTypes = {
  workspace: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const WorkspaceLineFragment = createFragmentContainer(WorkspaceLineComponent, {
  workspace: graphql`
      fragment WorkspaceLine_workspace on Workspace {
          id
          name
          ownedBy {
              node {
                  name
              }
          }
          created_at
          markingDefinitions {
              edges {
                  node {
                      id
                      definition
                  }
              }
          }
      }
  `,
});

export const WorkspaceLine = compose(
  inject18n,
  withStyles(styles),
)(WorkspaceLineFragment);

class WorkspaceLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Work/>
        </ListItemIcon>
        <ListItemText primary={
          <div>
            <div className={classes.bodyItem} style={inlineStyles.name}>
              <div className={classes.placeholder} style={{ width: '80%' }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.owner}>
              <div className={classes.placeholder} style={{ width: '70%' }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.created_at}>
              <div className={classes.placeholder} style={{ width: 140 }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.marking}>
              <div className={classes.placeholder} style={{ width: '90%' }}/>
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

WorkspaceLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const WorkspaceLineDummy = compose(
  inject18n,
  withStyles(styles),
)(WorkspaceLineDummyComponent);
