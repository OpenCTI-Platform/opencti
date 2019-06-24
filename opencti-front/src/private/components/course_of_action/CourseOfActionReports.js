import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../components/i18n';
import CourseOfActionHeader from './CourseOfActionHeader';
import EntityReports from '../report/EntityReports';

const styles = theme => ({
  container: {
    margin: 0,
  },
  paper: {
    minHeight: '100%',
    margin: '5px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class CourseOfActionReportsComponent extends Component {
  render() {
    const { classes, courseOfAction } = this.props;
    return (
      <div className={classes.container}>
        <CourseOfActionHeader courseOfAction={courseOfAction} />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <EntityReports entityId={courseOfAction.id} />
        </Paper>
      </div>
    );
  }
}

CourseOfActionReportsComponent.propTypes = {
  courseOfAction: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const CourseOfActionReports = createFragmentContainer(
  CourseOfActionReportsComponent,
  {
    courseOfAction: graphql`
      fragment CourseOfActionReports_courseOfAction on CourseOfAction {
        id
        ...CourseOfActionHeader_courseOfAction
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(CourseOfActionReports);
