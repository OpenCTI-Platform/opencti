import React, { Component } from 'react';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { MoreVert, CenterFocusStrong } from '@material-ui/icons';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import inject18n from '../../../components/i18n';
import MarkingDefinitionPopover from './MarkingDefinitionPopover';

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
  definition_type: {
    float: 'left',
    width: '25%',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  definition: {
    float: 'left',
    width: '25%',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  color: {
    float: 'left',
    width: '15%',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  level: {
    float: 'left',
    width: '10%',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  created: {
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

class MarkingDefinitionLineComponent extends Component {
  render() {
    const {
      fd, classes, markingDefinition, paginationOptions,
    } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <CenterFocusStrong/>
        </ListItemIcon>
        <ListItemText primary={
          <div>
            <div className={classes.bodyItem} style={inlineStyles.definition_type}>
                {propOr('-', 'definition_type', markingDefinition)}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.definition}>
              {propOr('-', 'definition', markingDefinition)}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.color}>
              {propOr('-', 'color', markingDefinition)}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.level}>
              {propOr('-', 'level', markingDefinition)}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.created}>
                {fd(propOr(null, 'created', markingDefinition))}
            </div>
          </div>
        }/>
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <MarkingDefinitionPopover markingDefinitionId={markingDefinition.id} paginationOptions={paginationOptions}/>
        </ListItemIcon>
      </ListItem>
    );
  }
}

MarkingDefinitionLineComponent.propTypes = {
  markingDefinition: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const MarkingDefinitionLineFragment = createFragmentContainer(MarkingDefinitionLineComponent, {
  markingDefinition: graphql`
        fragment MarkingDefinitionLine_markingDefinition on MarkingDefinition {
            id
            definition_type
            definition
            level
            color
            created
            modified
        }
    `,
});

export const MarkingDefinitionLine = compose(
  inject18n,
  withStyles(styles),
)(MarkingDefinitionLineFragment);

class MarkingDefinitionLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <CenterFocusStrong/>
        </ListItemIcon>
        <ListItemText primary={
          <div>
            <div className={classes.bodyItem} style={inlineStyles.definition_type}>
                <div className={classes.placeholder} style={{ width: '80%' }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.definition}>
              <div className={classes.placeholder} style={{ width: '70%' }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.color}>
              <div className={classes.placeholder} style={{ width: '60%' }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.level}>
              <div className={classes.placeholder} style={{ width: '80%' }}/>
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

MarkingDefinitionLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const MarkingDefinitionLineDummy = compose(
  inject18n,
  withStyles(styles),
)(MarkingDefinitionLineDummyComponent);
