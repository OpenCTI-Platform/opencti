import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import CourseOfAction from './CourseOfAction';

const subscription = graphql`
  subscription RootCoursesOfActionSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ... on CourseOfAction {
        ...CourseOfAction_courseOfAction
        ...CourseOfActionEditionContainer_courseOfAction
      }
    }
  }
`;

const courseOfActionQuery = graphql`
  query RootCourseOfActionQuery($id: String!) {
    courseOfAction(id: $id) {
      ...CourseOfAction_courseOfAction
      ...CourseOfActionOverview_courseOfAction
    }
  }
`;

class RootCourseOfAction extends Component {
  componentDidMount() {
    const {
      match: {
        params: { courseOfActionId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: courseOfActionId },
    });
    this.setState({ sub });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { courseOfActionId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={courseOfActionQuery}
          variables={{ id: courseOfActionId }}
          render={({ props }) => {
            if (props && props.courseOfAction) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/techniques/courses_of_action/:courseOfActionId"
                    render={routeProps => (
                      <CourseOfAction
                        {...routeProps}
                        courseOfAction={props.courseOfAction}
                      />
                    )}
                  />
                </div>
              );
            }
            return <div> &nbsp; </div>;
          }}
        />
      </div>
    );
  }
}

RootCourseOfAction.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootCourseOfAction);
