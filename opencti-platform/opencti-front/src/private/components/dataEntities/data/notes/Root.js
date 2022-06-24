/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  Route, Redirect, withRouter, Switch,
} from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer as QR } from 'react-relay';
import QueryRendererDarkLight from '../../../../../relay/environmentDarkLight';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../../relay/environment';
import TopBar from '../../../nav/TopBar';
import EntityNote from './EntityNote';
import Loader from '../../../../../components/Loader';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import { toastGenericError } from "../../../../../utils/bakedToast";

const subscription = graphql`
  subscription RootNotesSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      # ... on ThreatActor {
        # ...Device_device
        # ...DeviceEditionContainer_device
      # }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
    }
  }
`;

const NotesQuery = graphql`
  query RootNoteDataQuery($id: ID!) {
    cyioNote(id: $id) {
      id
      ...EntityNote_note
    }
  }
`;

class Notes extends Component {
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
      me,
      match: {
        params: { noteId },
      },
    } = this.props;
    const link = `/data/entities/notes/${noteId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <Route path="/data/entities/notes/:noteId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'victimology',
              'devices',
              'network',
              'software',
              'incidents',
              'malwares',
              'attack_patterns',
              'tools',
              'vulnerabilities',
              'observables',
              'infrastructures',
              'sightings',
            ]}
          />
        </Route>
        {/* <QueryRenderer */}
        <QR
          environment={QueryRendererDarkLight}
          query={NotesQuery}
          variables={{ id: noteId }}
          render={({ error, props, retry }) => {
            if (error) {
              console.error(error);
              toastGenericError('Failed to get Note data');
            }
            if (props) {
              if (props.cyioNote) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/data/entities/notes/:noteId"
                      render={(routeProps) => (
                        <EntityNote
                          {...routeProps}
                          me={me}
                          refreshQuery={retry}
                          note={props.cyioNote}
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

Notes.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(Notes);
