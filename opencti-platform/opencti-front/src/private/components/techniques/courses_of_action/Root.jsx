import { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { Route } from 'react-router-dom';
import * as R from 'ramda';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import withRouter from '../../../../utils/compat_router/withRouter';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import CourseOfAction from './CourseOfAction';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectMain from '@components/common/stix_domain_objects/StixDomainObjectMain';
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
import { PATH_COURSE_OF_ACTION, PATH_COURSES_OF_ACTION } from '@components/common/routes/paths';

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
                const basePath = PATH_COURSE_OF_ACTION(courseOfActionId);
                const paddingRight = getPaddingRight(location.pathname, basePath, false);
                return (
                  <div style={{ paddingRight }}>
                    <Breadcrumbs elements={[
                      { label: t('Techniques') },
                      { label: t('Courses of action'), link: PATH_COURSES_OF_ACTION },
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
                    <StixDomainObjectMain
                      basePath={basePath}
                      pages={{
                        overview:
                          <CourseOfAction courseOfActionData={props.courseOfAction} />,
                        content: (
                          <StixCoreObjectContentRoot
                            stixCoreObject={courseOfAction}
                          />
                        ),
                        files: (
                          <FileManager
                            id={courseOfActionId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.courseOfAction}
                          />
                        ),
                        history:
                          <StixCoreObjectHistory stixCoreObjectId={courseOfActionId} />,
                      }}
                      extraRoutes={(
                        <Route
                          path="/knowledge/*"
                          element={<CourseOfActionKnowledge courseOfAction={props.courseOfAction} />}
                        />
                      )}
                    />
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
