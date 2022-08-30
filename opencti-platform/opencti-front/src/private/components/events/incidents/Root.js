import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Incident from './Incident';
import IncidentKnowledge from './IncidentKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import IncidentPopover from './IncidentPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';

const subscription = graphql`
  subscription RootIncidentSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Incident {
        ...Incident_incident
        ...IncidentEditionContainer_incident
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...FilePendingViewer_entity
    }
  }
`;

const IncidentQuery = graphql`
  query RootIncidentQuery($id: String!) {
    incident(id: $id) {
      id
      standard_id
      name
      aliases
      x_opencti_graph_data
      ...Incident_incident
      ...IncidentKnowledge_incident
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...FilePendingViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
    settings {
      platform_enable_reference
    }
  }
`;

class RootIncident extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { incidentId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: incidentId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { incidentId },
      },
    } = this.props;
    const link = `/dashboard/events/incidents/${incidentId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <Route path="/dashboard/events/incidents/:incidentId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'attribution',
              'victimology',
              'attack_patterns',
              'malwares',
              'tools',
              'vulnerabilities',
              'observables',
            ]}
          />
        </Route>
        <QueryRenderer
          query={IncidentQuery}
          variables={{ id: incidentId }}
          render={({ props }) => {
            if (props) {
              if (props.incident) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/events/incidents/:incidentId"
                      render={(routeProps) => (
                        <Incident {...routeProps} incident={props.incident} />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/events/incidents/:incidentId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/events/incidents/${incidentId}/knowledge/overview`}
                        />
                      )}
                    />
                    <Route
                      path="/dashboard/events/incidents/:incidentId/knowledge"
                      render={(routeProps) => (
                        <IncidentKnowledge
                          {...routeProps}
                          incident={props.incident}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/events/incidents/:incidentId/analysis"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.incident}
                            PopoverComponent={<IncidentPopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Incident',
                            )}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.incident
                            }
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/events/incidents/:incidentId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.incident}
                            PopoverComponent={<IncidentPopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Incident',
                            )}
                          />
                          <FileManager
                            {...routeProps}
                            id={incidentId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.incident}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/events/incidents/:incidentId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.incident}
                            PopoverComponent={<IncidentPopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Incident',
                            )}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={incidentId}
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

RootIncident.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootIncident);
