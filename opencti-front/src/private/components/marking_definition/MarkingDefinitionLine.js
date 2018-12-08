import React, { Component } from 'react';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { KeyboardArrowRight, CenterFocusStrong } from '@material-ui/icons';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import inject18n from '../../../components/i18n';

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
    width: '40%',
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

class MarkingDefinitionLineComponent extends Component {
  render() {
    const { fd, classes, markingDefinition } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <CenterFocusStrong/>
        </ListItemIcon>
        <ListItemText primary={
          <div>
            <div className={classes.bodyItem} style={inlineStyles.definition_type}>
                {markingDefinition.definition_type}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.definition}>
              {markingDefinition.definition}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.created}>
                {fd(markingDefinition.created)}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.modified}>
                {fd(markingDefinition.modified)}
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

MarkingDefinitionLineComponent.propTypes = {
  markingDefinition: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const MarkingDefinitionLineFragment = createFragmentContainer(MarkingDefinitionLineComponent, {
  markingDefinition: graphql`
        fragment MarkingDefinitionLine_markingDefinition on MarkingDefinition {
            id,
            definition_type,
            definition,
            created,
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

MarkingDefinitionLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const MarkingDefinitionLineDummy = compose(
  inject18n,
  withStyles(styles),
)(MarkingDefinitionLineDummyComponent);
