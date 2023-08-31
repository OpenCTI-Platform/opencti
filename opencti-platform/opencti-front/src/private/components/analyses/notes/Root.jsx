import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Note from './Note';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import ContainerHeader from '../../common/containers/ContainerHeader';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import NotePopover from './NotePopover';

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
      match: {
        params: { noteId },
      },
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
      match: {
        params: { noteId },
      },
    } = this.props;
    return (
      <div>
        <TopBar />
        <QueryRenderer
          query={noteQuery}
          variables={{ id: noteId }}
          render={({ props }) => {
            if (props) {
              if (props.note) {
                return (
                  <div>
                    <Route
                      exact
                      path="/dashboard/analyses/notes/:noteId"
                      render={(routeProps) => (
                        <Note {...routeProps} note={props.note} />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/analyses/notes/:noteId/files"
                      render={(routeProps) => (
                        <>
                          <ContainerHeader
                            container={props.note}
                            PopoverComponent={<NotePopover note={props.note} />}
                          />
                          <FileManager
                            {...routeProps}
                            id={noteId}
                            connectorsExport={props.connectorsForExport}
                            connectorsImport={props.connectorsForImport}
                            entity={props.note}
                          />
                        </>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/analyses/notes/:noteId/history"
                      render={(routeProps) => (
                        <>
                          <ContainerHeader
                            container={props.note}
                            PopoverComponent={<NotePopover note={props.note} />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={noteId}
                            withoutRelations={true}
                          />
                        </>
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

RootNote.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default withRouter(RootNote);
