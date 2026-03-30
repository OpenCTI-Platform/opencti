import { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes } from 'react-router';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import StixDomainObjectTabsBox from '@components/common/stix_domain_objects/StixDomainObjectTabsBox';
import withRouter from '../../../../utils/compat_router/withRouter';
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
import { getPaddingRight } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import CourseOfActionEdition from './CourseOfActionEdition';
import CourseOfActionDeletion from './CouseOfActionDeletion';

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
      draftVersion {
        draft_id
        draft_operation
      }
      standard_id
      entity_type
      name
      x_opencti_aliases
      currentUserAccessRight
      ...CourseOfAction_courseOfAction
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...StixCoreObjectContent_stixCoreObject
      ...StixCoreObjectSharingListFragment
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
      <div>
        <QueryRenderer
          query={courseOfActionQuery}
          variables={{ id: courseOfActionId }}
          render={({ props }) => {
            if (props) {
              if (props.courseOfAction) {
                const { courseOfAction } = props;
                const paddingRight = getPaddingRight(location.pathname, courseOfAction.id, '/dashboard/techniques/courses_of_action', false);
                return (
                  <div style={{ paddingRight }}>
                    <Breadcrumbs elements={[
                      { label: t('Techniques') },
                      { label: t('Courses of action'), link: '/dashboard/techniques/courses_of_action' },
                      { label: courseOfAction.name, current: true },
                    ]}
                    />
                    <StixDomainObjectHeader
                      entityType="Course-Of-Action"
                      stixDomainObject={courseOfAction}
                      EditComponent={(
                        <Security needs={[KNOWLEDGE_KNUPDATE]}>
                          <CourseOfActionEdition courseOfActionId={courseOfAction.id} />
                        </Security>
                      )}
                      DeleteComponent={({ isOpen, onClose }) => (
                        <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                          <CourseOfActionDeletion id={courseOfAction.id} isOpen={isOpen} handleClose={onClose} />
                        </Security>
                      )}
                      isOpenctiAlias={true}
                      redirectToContent={true}
                      enableEnrollPlaybook={true}
                    />
                    <StixDomainObjectTabsBox
                      basePath="/dashboard/techniques/courses_of_action"
                      entity={courseOfAction}
                      tabs={[
                        'overview',
                        'content',
                        'files',
                        'history',
                      ]}
                    />
                    <Routes>
                      <Route
                        path="/"
                        element={
                          <CourseOfAction courseOfActionData={props.courseOfAction} />
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
                        element={(
                          <StixCoreObjectContentRoot
                            stixCoreObject={courseOfAction}
                          />
                        )}
                      />
                      <Route
                        path="/files"
                        element={(
                          <FileManager
                            id={courseOfActionId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.courseOfAction}
                          />
                        )}
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
