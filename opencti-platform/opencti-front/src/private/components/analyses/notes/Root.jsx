import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link, Route, Routes } from 'react-router-dom';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import Note from './Note';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import ContainerHeader from '../../common/containers/ContainerHeader';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import inject18n from '../../../../components/i18n';
import { CollaborativeSecurity } from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import withRouter from '../../../../utils/compat-router/withRouter';
import NoteEdition from './NoteEdition';
import RelateComponentContextProvider from '../../common/menus/RelateComponentProvider';

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

class RootNote extends Component {
  constructor(props) {
    super(props);
    const {
      params: { noteId },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: noteId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      t,
      location,
      params: { noteId },
    } = this.props;
    return (
      <QueryRenderer
        query={noteQuery}
        variables={{ id: noteId }}
        render={({ props }) => {
          if (props) {
            if (props.note) {
              const { note } = props;
              return (
                <RelateComponentContextProvider>
                  <div
                    style={{
                      paddingRight: location.pathname.includes(
                        `/dashboard/analyses/notes/${note.id}/knowledge`,
                      )
                        ? 200
                        : 0,
                    }}
                  >
                    <CollaborativeSecurity
                      data={note}
                      needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}
                      placeholder={
                        <ContainerHeader
                          container={note}
                          EditComponent={<NoteEdition noteId={note.id} />}
                        />
                        }
                    >
                      <ContainerHeader
                        container={props.note}
                        EditComponent={<NoteEdition noteId={note.id} />}
                        redirectToContent={false}
                      />
                    </CollaborativeSecurity>
                    <Box
                      sx={{
                        borderBottom: 1,
                        borderColor: 'divider',
                        marginBottom: 4,
                      }}
                    >
                      <Tabs
                        value={
                            location.pathname
                          }
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/analyses/notes/${note.id}`}
                          value={`/dashboard/analyses/notes/${note.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/analyses/notes/${note.id}/files`}
                          value={`/dashboard/analyses/notes/${note.id}/files`}
                          label={t('Data')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/analyses/notes/${note.id}/history`}
                          value={`/dashboard/analyses/notes/${note.id}/history`}
                          label={t('History')}
                        />
                      </Tabs>
                    </Box>
                    <Routes>
                      <Route
                        path="/dashboard/analyses/notes/:noteId"
                        element={
                          <Note note={props.note} />
                          }
                      />
                      <Route
                        path="/dashboard/analyses/notes/:noteId/files"
                        element={
                          <FileManager
                            id={noteId}
                            connectorsExport={props.connectorsForExport}
                            connectorsImport={props.connectorsForImport}
                            entity={props.note}
                          />
                          }
                      />
                      <Route
                        path="/history"
                        element={
                          <StixCoreObjectHistory
                            stixCoreObjectId={noteId}
                            withoutRelations={true}
                          />
                          }
                      />
                      <Route
                        path="/knowledge/relations/:relationId"
                        element={
                          <StixCoreRelationship
                            entityId={props.note.id}
                          />
                          }
                      />
                    </Routes>
                  </div>
                </RelateComponentContextProvider>
              );
            }
            return <ErrorNotFound />;
          }
          return <Loader />;
        }}
      />
    );
  }
}

RootNote.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootNote);
