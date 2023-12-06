import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link, Route, Routes } from 'react-router-dom';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import * as R from 'ramda';
import withRouter from '../../../../utils/compat-router/withRouter';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import CourseOfAction from './CourseOfAction';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import CourseOfActionKnowledge from './CourseOfActionKnowledge';
import inject18n from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import CourseOfActionEdition from './CourseOfActionEdition';
import CreateRelationshipButtonComponent from '../../common/menus/RelateComponent';
import RelateComponentContextProvider from '../../common/menus/RelateComponentProvider';

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
      created_at
      updated_at
      ...CourseOfAction_courseOfAction
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
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
    return (
      <RelateComponentContextProvider>
        <QueryRenderer
          query={courseOfActionQuery}
          variables={{ id: courseOfActionId }}
          render={({ props }) => {
            if (props) {
              if (props.courseOfAction) {
                const { courseOfAction } = props;
                return (
                  <div>
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Techniques') },
                      { label: t('Courses of action'), link: '/dashboard/techniques/courses_of_action' },
                      { label: courseOfAction.name, current: true },
                    ]}
                    />
                    <StixDomainObjectHeader
                      entityType="Course-Of-Action"
                      disableSharing={true}
                      stixDomainObject={props.courseOfAction}
                      EditComponent={<Security needs={[KNOWLEDGE_KNUPDATE]}>
                        <CourseOfActionEdition
                          courseOfActionId={courseOfAction.id}
                        />
                      </Security>}
                      RelateComponent={<CreateRelationshipButtonComponent
                        id={courseOfAction.id}
                        defaultStartTime={courseOfAction.created_at}
                        defaultStopTime={courseOfAction.updated_at}
                                       />}
                    />
                    <Box
                      sx={{
                        borderBottom: 1,
                        borderColor: 'divider',
                        marginBottom: 4,
                      }}
                    >
                      <Tabs
                        value={
                          location.pathname.includes(
                            `/dashboard/techniques/courses_of_action/${courseOfAction.id}/knowledge`,
                          )
                            ? `/dashboard/techniques/courses_of_action/${courseOfAction.id}`
                            : location.pathname
                        }
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/techniques/courses_of_action/${courseOfAction.id}`}
                          value={`/dashboard/techniques/courses_of_action/${courseOfAction.id}`}
                          label={t('Overview')}
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
      </RelateComponentContextProvider>
    );
  }
}

RootCourseOfAction.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootCourseOfAction);
