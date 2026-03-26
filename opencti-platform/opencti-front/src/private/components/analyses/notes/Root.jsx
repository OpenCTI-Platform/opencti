import { useMemo } from 'react';
import { Route, Routes, useParams } from 'react-router-dom';
import { graphql, useSubscription } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { useEntityTypeDisplayName } from '../../../../utils/hooks/useEntityTypeDisplayName';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import StixDomainObjectTabsBox from '@components/common/stix_domain_objects/StixDomainObjectTabsBox';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import { QueryRenderer } from '../../../../relay/environment';
import Note from './Note';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import ContainerHeader from '../../common/containers/ContainerHeader';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import Security, { CollaborativeSecurity } from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import NoteEdition from './NoteEdition';
import NoteDeletion from './NoteDeletion';

const subscription = graphql`
    subscription RootNoteSubscription($id: ID!) {
        stixDomainObject(id: $id) {
            ... on Note {
                ...Note_note
                ...NoteEditionContainer_note
            }
            ...FileImportViewer_entity
            ...FileExportViewer_entity
            ...FileExternalReferencesViewer_entity
            ...WorkbenchFileViewer_entity
        }
    }
`;

const noteQuery = graphql`
    query RootNoteQuery($id: String!) {
        note(id: $id) {
            id
            standard_id
            entity_type
            ...Note_note
            ...NoteDetails_note
            ...ContainerHeader_container
            ...ContainerStixDomainObjects_container
            ...ContainerStixObjectsOrStixRelationships_container
            ...FileImportViewer_entity
            ...FileExportViewer_entity
            ...FileExternalReferencesViewer_entity
            ...WorkbenchFileViewer_entity
        }
        connectorsForExport {
            ...FileManager_connectorsExport
        }
        connectorsForImport {
            ...FileManager_connectorsImport
        }
    }
`;

const RootNote = () => {
  const { noteId } = useParams();
  const subConfig = useMemo(
    () => ({
      subscription,
      variables: { id: noteId },
    }),
    [noteId],
  );
  const { t_i18n } = useFormatter();
  const entityTypeDisplayName = useEntityTypeDisplayName();
  useSubscription(subConfig);
  return (
    <>
      <QueryRenderer
        query={noteQuery}
        variables={{ id: noteId }}
        render={({ props }) => {
          if (props) {
            if (props.note) {
              const { note } = props;
              return (
                <>
                  <Breadcrumbs elements={[
                    { label: t_i18n('Analyses') },
                    { label: entityTypeDisplayName('Note', { plural: true }), link: '/dashboard/analyses/notes' },
                  ]}
                  />
                  <CollaborativeSecurity
                    data={note}
                    needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}
                    placeholder={(
                      <ContainerHeader
                        container={props.note}
                        EditComponent={(
                          <CollaborativeSecurity data={note} needs={[KNOWLEDGE_KNUPDATE]}>
                            <NoteEdition noteId={note.id} />
                          </CollaborativeSecurity>
                        )}
                        DeleteComponent={({ isOpen, onClose }) => (
                          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                            <NoteDeletion id={note.id} isOpen={isOpen} handleClose={onClose} />
                          </Security>
                        )}
                        redirectToContent={false}
                        disableAuthorizedMembers={true}
                        enableEnricher={true}
                        enableEnrollPlaybook={true}
                      />
                    )}
                  >
                    <ContainerHeader
                      container={note}
                      EditComponent={(
                        <CollaborativeSecurity data={note} needs={[KNOWLEDGE_KNUPDATE]}>
                          <NoteEdition noteId={note.id} />
                        </CollaborativeSecurity>
                      )}
                      DeleteComponent={({ isOpen, onClose }) => (
                        <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                          <NoteDeletion id={note.id} isOpen={isOpen} handleClose={onClose} />
                        </Security>
                      )}
                      redirectToContent={false}
                      disableAuthorizedMembers={true}
                      enableEnricher={true}
                      enableEnrollPlaybook={true}
                    />
                  </CollaborativeSecurity>
                  <StixDomainObjectTabsBox
                    basePath="/dashboard/analyses/notes"
                    entity={note}
                    tabs={[
                      'overview',
                      'files',
                      'history',
                    ]}
                  />
                  <Routes>
                    <Route
                      path="/"
                      element={<Note noteFragment={note} enableReferences={false} />}
                    />
                    <Route
                      path="/files"
                      element={(
                        <FileManager
                          id={noteId}
                          connectorsExport={props.connectorsForExport}
                          connectorsImport={props.connectorsForImport}
                          entity={note}
                        />
                      )}
                    />
                    <Route
                      path="/history"
                      element={<StixCoreObjectHistory stixCoreObjectId={noteId} withoutRelations />}
                    />
                    <Route
                      path="/knowledge/relations/:relationId"
                      element={<StixCoreRelationship entityId={note.id} />}
                    />
                  </Routes>
                </>
              );
            }
            return <ErrorNotFound />;
          }
          return <Loader />;
        }}
      />
    </>
  );
};

export default RootNote;
