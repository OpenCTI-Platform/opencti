import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import CourseOfAction from './CourseOfAction';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import CourseOfActionPopover from './CourseOfActionPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';

const subscription = graphql`
  subscription RootCoursesOfActionSubscription($id: ID!) {
    stixDomainObject(id: $id) {
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
      x_opencti_aliases
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
            if (props) {
              if (props.courseOfAction) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/arsenal/courses_of_action/:courseOfActionId"
                      render={(routeProps) => (
                        <CourseOfAction
                          {...routeProps}
                          courseOfAction={props.courseOfAction}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/courses_of_action/:courseOfActionId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.courseOfAction}
                            PopoverComponent={<CourseOfActionPopover />}
                          />
                          <FileManager
                            {...routeProps}
                            id={courseOfActionId}
                            connectorsImport={[]}
                            connectorsExport={props.connectorsForExport}
                            entity={props.courseOfAction}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/courses_of_action/:courseOfActionId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.courseOfAction}
                            PopoverComponent={<CourseOfActionPopover />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={courseOfActionId}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/courses_of_action/:courseOfActionId/relations/:relationId"
                      render={(routeProps) => (
                        <StixCoreRelationship
                          entityId={courseOfActionId}
                          {...routeProps}
                        />
                      )}
                    />
                  </Switch>
                );
              }
              return <ErrorNotFound />;
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
