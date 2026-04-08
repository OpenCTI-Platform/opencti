import { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import withRouter from '../../../../utils/compat_router/withRouter';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import StixCyberObservable from '../stix_cyber_observables/StixCyberObservable';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCyberObservableHeader from '../stix_cyber_observables/StixCyberObservableHeader';
import StixDomainObjectMain from '@components/common/stix_domain_objects/StixDomainObjectMain';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import FileManager from '../../common/files/FileManager';
import inject18n from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getPaddingRight } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import StixCyberObservableDeletion from '../stix_cyber_observables/StixCyberObservableDeletion';
import ArtifactKnowledge from './ArtifactKnowledge';
import { PATH_ARTIFACT, PATH_ARTIFACTS } from '@components/common/routes/paths';

const subscription = graphql`
  subscription RootArtifactSubscription($id: ID!) {
    stixCyberObservable(id: $id) {
      ...StixCyberObservable_stixCyberObservable
      ...StixCyberObservableEditionContainer_stixCyberObservable
      ...StixCyberObservableKnowledge_stixCyberObservable
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const rootArtifactQuery = graphql`
  query RootArtifactQuery($id: String!) {
    stixCyberObservable(id: $id) {
      id
      draftVersion {
        draft_id
        draft_operation
      }
      standard_id
      entity_type
      observable_value
      ...StixCyberObservable_stixCyberObservable
      ...StixCyberObservableHeader_stixCyberObservable
      ...StixCyberObservableDetails_stixCyberObservable
      ...StixCyberObservableIndicators_stixCyberObservable
      ...StixCyberObservableKnowledge_stixCyberObservable
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

class RootArtifact extends Component {
  constructor(props) {
    super(props);
    const {
      params: { observableId },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: observableId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      t,
      location,
      params: { observableId },
    } = this.props;
    const basePath = PATH_ARTIFACT(observableId);
    const link = `${basePath}/knowledge`;
    return (
      <>
        <QueryRenderer
          query={rootArtifactQuery}
          variables={{ id: observableId, relationship_type: 'indicates' }}
          render={({ props }) => {
            if (props) {
              if (props.stixCyberObservable) {
                const { stixCyberObservable } = props;
                const paddingRight = getPaddingRight(location.pathname, basePath, false);
                return (
                  <div style={{ paddingRight }}>
                    <Breadcrumbs elements={[
                      { label: t('Observations') },
                      { label: t('Artifacts'), link: PATH_ARTIFACTS },
                      { label: stixCyberObservable.observable_value, current: true },
                    ]}
                    />
                    <StixCyberObservableHeader
                      stixCyberObservable={stixCyberObservable}
                      enableEnrollPlaybook={true}
                      DeleteComponent={({ isOpen, onClose }) => (
                        <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                          <StixCyberObservableDeletion id={stixCyberObservable.id} isOpen={isOpen} handleClose={onClose} />
                        </Security>
                      )}
                    />
                    <StixDomainObjectMain
                      entityType="Artifact"
                      basePath={basePath}
                      pages={{
                        overview: (
                          <StixCyberObservable
                            stixCyberObservableData={stixCyberObservable}
                          />
                        ),
                        knowledge: (
                          <ArtifactKnowledge
                            artifact={stixCyberObservable}
                            connectorsForImport={props.connectorsForImport}
                          />
                        ),
                        content: (
                          <StixCoreObjectContentRoot
                            stixCoreObject={stixCyberObservable}
                          />
                        ),
                        sightings: (
                          <EntityStixSightingRelationships
                            entityId={observableId}
                            entityLink={link}
                            noRightBar={true}
                            noPadding={true}
                            stixCoreObjectTypes={[
                              'Region',
                              'Country',
                              'City',
                              'Position',
                              'Sector',
                              'Organization',
                              'Individual',
                              'System',
                            ]}
                          />
                        ),
                        files: (
                          <FileManager
                            id={observableId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.stixCyberObservable}
                            isArtifact={true}
                            directDownload={true}
                          />
                        ),
                        history: (
                          <StixCoreObjectHistory
                            stixCoreObjectId={observableId}
                          />
                        ),
                      }}
                    />
                  </div>
                );
              }
              return <ErrorNotFound />;
            }
            return <Loader />;
          }}
        />
      </>
    );
  }
}

RootArtifact.propTypes = {
  children: PropTypes.node,
  params: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootArtifact);
