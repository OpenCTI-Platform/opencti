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
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';
import FileManager from '../../common/files/FileManager';
import CourseOfActionPopover from './CourseOfActionPopover';
import Loader from '../../../../components/Loader';
import StixObjectHistory from '../../common/stix_object/StixObjectHistory';

const subscription = graphql`
  subscription RootCoursesOfActionSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ... on CourseOfAction {
        ...CourseOfAction_courseOfAction
        ...CourseOfActionEditionContainer_courseOfAction
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
  }
`;

const courseOfActionQuery = graphql`
  query RootCourseOfActionQuery($id: String!) {
    courseOfAction(id: $id) {
      id
      name
      alias
      ...CourseOfAction_courseOfAction
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
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
                    render={(routeProps) => (
                      <CourseOfAction
                        {...routeProps}
                        courseOfAction={props.courseOfAction}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/techniques/courses_of_action/:courseOfActionId/files"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainEntityHeader
                          stixDomainEntity={props.courseOfAction}
                          PopoverComponent={<CourseOfActionPopover />}
                        />
                        <FileManager
                          {...routeProps}
                          id={courseOfActionId}
                          connectorsExport={props.connectorsForExport}
                          entity={props.courseOfAction}
                        />
                      </React.Fragment>
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/techniques/courses_of_action/:courseOfActionId/history"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainEntityHeader
                          stixDomainEntity={props.courseOfAction}
                          PopoverComponent={<CourseOfActionPopover />}
                        />
                        <StixObjectHistory
                          {...routeProps}
                          entityId={courseOfActionId}
                        />
                      </React.Fragment>
                    )}
                  />
                </div>
              );
            }
            return <Loader />;
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
