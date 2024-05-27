import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link, Route, Routes } from 'react-router-dom';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import * as R from 'ramda';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import withRouter from '../../../../utils/compat-router/withRouter';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import CourseOfAction from './CourseOfAction';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import CourseOfActionPopover from './CourseOfActionPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import CourseOfActionKnowledge from './CourseOfActionKnowledge';
import inject18n from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';

const subscription = graphql`
  subscription RootCoursesOfActionSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on CourseOfAction {
        ...CourseOfAction_courseOfAction
        ...CourseOfActionEditionContainer_courseOfAction
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const courseOfActionQuery = graphql`
  query RootCourseOfActionQuery($id: String!) {
    courseOfAction(id: $id) {
      id
      standard_id
      entity_type
      name
      x_opencti_aliases
      ...CourseOfAction_courseOfAction
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...StixCoreObjectContent_stixCoreObject
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

class RootCourseOfAction extends Component {
  constructor(props) {
    super(props);
    const {
      params: { courseOfActionId },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: courseOfActionId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      t,
      location,
      params: { courseOfActionId },
    } = this.props;
    const getCurrentTab = (courseOfAction) => {
      if (location.pathname.includes(`/dashboard/techniques/courses_of_action/${courseOfAction.id}/knowledge`)) return `/dashboard/techniques/courses_of_action/${courseOfAction.id}/knowledge`;
      if (location.pathname.includes(`/dashboard/techniques/courses_of_action/${courseOfAction.id}/content`)) return `/dashboard/techniques/courses_of_action/${courseOfAction.id}/content`;
      return location.pathname;
    };
    return (
      <div>
        <QueryRenderer
          query={courseOfActionQuery}
          variables={{ id: courseOfActionId }}
          render={({ props }) => {
            if (props) {
              if (props.courseOfAction) {
                const { courseOfAction } = props;
                let paddingRight = 0;
                if (
                  location.pathname.includes(
                    `/dashboard/techniques/courses_of_action/${courseOfAction.id}/knowledge`,
                  )
                ) {
                  paddingRight = 200;
                }
                if (
                  location.pathname.includes(
                    `/dashboard/techniques/courses_of_action/${courseOfAction.id}/content`,
                  )
                ) {
                  paddingRight = 350;
                }
                if (
                  location.pathname.includes(
                    `/dashboard/techniques/courses_of_action/${courseOfAction.id}/content/mapping`,
                  )
                ) {
                  paddingRight = 0;
                }
                return (
                  <div style={{ paddingRight }}>
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Techniques') },
                      { label: t('Courses of action'), link: '/dashboard/techniques/courses_of_action' },
                      { label: courseOfAction.name, current: true },
                    ]}
                    />
                    <StixDomainObjectHeader
                      entityType="Course-Of-Action"
                      disableSharing={true}
                      stixDomainObject={courseOfAction}
                      PopoverComponent={<CourseOfActionPopover />}
                      isOpenctiAlias={true}
                    />
                    <Box
                      sx={{
                        borderBottom: 1,
                        borderColor: 'divider',
                        marginBottom: 4,
                      }}
                    >
                      <Tabs
                        value={getCurrentTab(courseOfAction)}
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/techniques/courses_of_action/${courseOfAction.id}`}
                          value={`/dashboard/techniques/courses_of_action/${courseOfAction.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/techniques/courses_of_action/${courseOfAction.id}/content`}
                          value={`/dashboard/techniques/courses_of_action/${courseOfAction.id}/content`}
                          label={t('Content')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/techniques/courses_of_action/${courseOfAction.id}/files`}
                          value={`/dashboard/techniques/courses_of_action/${courseOfAction.id}/files`}
                          label={t('Data')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/techniques/courses_of_action/${courseOfAction.id}/history`}
                          value={`/dashboard/techniques/courses_of_action/${courseOfAction.id}/history`}
                          label={t('History')}
                        />
                      </Tabs>
                    </Box>
                    <Routes>
                      <Route
                        path="/"
                        element={
                          <CourseOfAction courseOfAction={props.courseOfAction} />
                        }
                      />
                      <Route
                        path="/knowledge/*"
                        element={
                          <CourseOfActionKnowledge courseOfAction={props.courseOfAction} />
                        }
                      />
                      <Route
                        path="/content/*"
                        element={
                          <StixCoreObjectContentRoot
                            stixCoreObject={courseOfAction}
                          />
                        }
                      />
                      <Route
                        path="/files"
                        element={
                          <FileManager
                            id={courseOfActionId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.courseOfAction}
                          />
                        }
                      />
                      <Route
                        path="/history"
                        element={
                          <StixCoreObjectHistory stixCoreObjectId={courseOfActionId} />
                        }
                      />
                    </Routes>
                  </div>
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
};

export default R.compose(inject18n, withRouter)(RootCourseOfAction);
