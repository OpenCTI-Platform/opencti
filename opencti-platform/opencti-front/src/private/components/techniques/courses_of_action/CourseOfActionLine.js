import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { KeyboardArrowRight } from '@material-ui/icons';
import { ProgressWrench } from 'mdi-material-ui';
import inject18n from '../../../../components/i18n';

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
    color: theme.palette.grey[700],
  },
});

const inlineStyles = {
  name: {
    float: 'left',
    width: '55%',
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

class CourseOfActionLineComponent extends Component {
  render() {
    const {
      fd, classes, courseOfAction,
    } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        component={Link}
        to={`/dashboard/techniques/courses_of_action/${courseOfAction.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ProgressWrench />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div className={classes.bodyItem} style={inlineStyles.name}>
                {courseOfAction.name}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.created}>
                {fd(courseOfAction.created)}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.modified}>
                {fd(courseOfAction.modified)}
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

CourseOfActionLineComponent.propTypes = {
  courseOfAction: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const CourseOfActionLineFragment = createFragmentContainer(
  CourseOfActionLineComponent,
  {
    courseOfAction: graphql`
      fragment CourseOfActionLine_courseOfAction on CourseOfAction {
        id
        name
        created
        modified
      }
    `,
  },
);

export const CourseOfActionLine = compose(
  inject18n,
  withStyles(styles),
)(CourseOfActionLineFragment);

class CourseOfActionLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <ProgressWrench />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
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

CourseOfActionLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const CourseOfActionLineDummy = compose(
  inject18n,
  withStyles(styles),
)(CourseOfActionLineDummyComponent);
