import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Event from './Event';
import EventKnowledge from './EventKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import EventPopover from './EventPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';

const subscription = graphql`
  subscription RootEventsSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Event {
        ...Event_event
        ...EventEditionContainer_event
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const eventQuery = graphql`
  query RootEventQuery($id: String!) {
    event(id: $id) {
      id
      name
      aliases
      ...Event_event
      ...EventKnowledge_event
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

class RootEvent extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { eventId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: eventId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      match: {
        params: { eventId },
      },
    } = this.props;
    const link = `/dashboard/entities/events/${eventId}/knowledge`;
    return (
      <div>
        <TopBar />
        <Route path="/dashboard/entities/events/:eventId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'locations',
              'threats',
              'threat_actors',
              'intrusion_sets',
              'campaigns',
              'incidents',
              'malwares',
              'attack_patterns',
              'tools',
              'observables',
            ]}
          />
        </Route>
        <QueryRenderer
          query={eventQuery}
          variables={{ id: eventId }}
          render={({ props }) => {
            if (props) {
              if (props.event) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/entities/events/:eventId"
                      render={(routeProps) => (
                        <Event {...routeProps} event={props.event} />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/events/:eventId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/entities/events/${eventId}/knowledge/overview`}
                        />
                      )}
                    />
                    <Route
                      path="/dashboard/entities/events/:eventId/knowledge"
                      render={(routeProps) => (
                        <EventKnowledge {...routeProps} event={props.event} />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/events/:eventId/analyses"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Event'}
                            stixDomainObject={props.event}
                            PopoverComponent={<EventPopover />}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={props.event}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/events/:eventId/sightings"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Event'}
                            stixDomainObject={props.event}
                            PopoverComponent={<EventPopover />}
                          />
                          <EntityStixSightingRelationships
                            entityId={props.event.id}
                            entityLink={link}
                            noPadding={true}
                            isTo={true}
                            {...routeProps}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/events/:eventId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Event'}
                            stixDomainObject={props.event}
                            PopoverComponent={<EventPopover />}
                          />
                          <FileManager
                            {...routeProps}
                            id={eventId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.event}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/events/:eventId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Event'}
                            stixDomainObject={props.event}
                            PopoverComponent={<EventPopover />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={eventId}
                          />
                        </React.Fragment>
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

RootEvent.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default withRouter(RootEvent);
