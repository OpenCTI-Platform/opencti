import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { MoreVert, CenterFocusStrong } from '@material-ui/icons';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';
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
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

const inlineStyles = {
  definition_type: {
    float: 'left',
    width: '25%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  definition: {
    float: 'left',
    width: '25%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  color: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  level: {
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

class MarkingDefinitionLineComponent extends Component {
  render() {
    const {
      fd, classes, markingDefinition, paginationOptions,
    } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <CenterFocusStrong />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={inlineStyles.definition_type}
              >
                {markingDefinition.definition_type}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.definition}>
                {markingDefinition.definition}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.color}>
                {markingDefinition.color}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.level}>
                {markingDefinition.level}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.created}>
                {fd(markingDefinition.created)}
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <MarkingDefinitionPopover
            markingDefinitionId={markingDefinition.id}
            paginationOptions={paginationOptions}
          />
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

const MarkingDefinitionLineFragment = createFragmentContainer(
  MarkingDefinitionLineComponent,
  {
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
  },
);

export const MarkingDefinitionLine = compose(
  inject18n,
  withStyles(styles),
)(MarkingDefinitionLineFragment);

class MarkingDefinitionLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <CenterFocusStrong />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={inlineStyles.definition_type}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.definition}>
                <div className="fakeItem" style={{ width: '70%' }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.color}>
                <div className="fakeItem" style={{ width: '60%' }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.level}>
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.created}>
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <MoreVert />
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
