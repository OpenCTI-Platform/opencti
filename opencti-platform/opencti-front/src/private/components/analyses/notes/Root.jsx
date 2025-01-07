import React, { useMemo } from 'react';
import PropTypes from 'prop-types';
import { Link, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import { QueryRenderer } from '../../../../relay/environment';
import Note from './Note';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import ContainerHeader from '../../common/containers/ContainerHeader';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import NotePopover from './NotePopover';
import { CollaborativeSecurity } from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import NoteEdition from './NoteEdition';

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
  const location = useLocation();
  const { t_i18n } = useFormatter();
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
                    { label: t_i18n('Notes'), link: '/dashboard/analyses/notes' },
                  ]}
                  />
                  <CollaborativeSecurity
                    data={note}
                    needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}
                    placeholder={
                      <ContainerHeader
                        container={props.note}
                        PopoverComponent={<NotePopover note={note}/>}
                        EditComponent={
                          <CollaborativeSecurity data={note} needs={[KNOWLEDGE_KNUPDATE]}>
                            <NoteEdition noteId={note.id}/>
                          </CollaborativeSecurity>
                        }
                        redirectToContent={false}
                        disableAuthorizedMembers={true}
                        enableEnricher={true}
                        enableEnrollPlaybook={true}
                      />
                    }
                  >
                    <ContainerHeader
                      container={note}
                      PopoverComponent={<NotePopover note={note}/>}
                      EditComponent={
                        <CollaborativeSecurity data={note} needs={[KNOWLEDGE_KNUPDATE]}>
                          <NoteEdition noteId={note.id}/>
                        </CollaborativeSecurity>
                      }
                      redirectToContent={false}
                      disableAuthorizedMembers={true}
                      enableEnricher={true}
                      enableEnrollPlaybook={true}
                    />
                  </CollaborativeSecurity>
                  <Box sx={{ borderBottom: 1, borderColor: 'divider', marginBottom: 3 }}>
                    <Tabs value={location.pathname}>
                      <Tab
                        component={Link}
                        to={`/dashboard/analyses/notes/${note.id}`}
                        value={`/dashboard/analyses/notes/${note.id}`}
                        label={t_i18n('Overview')}
                      />
                      <Tab
                        component={Link}
                        to={`/dashboard/analyses/notes/${note.id}/files`}
                        value={`/dashboard/analyses/notes/${note.id}/files`}
                        label={t_i18n('Data')}
                      />
                      <Tab
                        component={Link}
                        to={`/dashboard/analyses/notes/${note.id}/history`}
                        value={`/dashboard/analyses/notes/${note.id}/history`}
                        label={t_i18n('History')}
                      />
                    </Tabs>
                  </Box>
                  <Routes>
                    <Route
                      path="/"
                      element={<Note noteFragment={note} enableReferences={false}/>}
                    />
                    <Route
                      path="/files"
                      element={
                        <FileManager
                          id={noteId}
                          connectorsExport={props.connectorsForExport}
                          connectorsImport={props.connectorsForImport}
                          entity={note}
                        />
                      }
                    />
                    <Route
                      path="/history"
                      element={<StixCoreObjectHistory stixCoreObjectId={noteId} withoutRelations/>}
                    />
                    <Route
                      path="/knowledge/relations/:relationId"
                      element={<StixCoreRelationship entityId={note.id}/>}
                    />
                  </Routes>
                </>
              );
            }
            return <ErrorNotFound/>;
          }
          return <Loader/>;
        }}
      />
    </>
  );
};

RootNote.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default RootNote;
