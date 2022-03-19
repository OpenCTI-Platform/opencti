import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import ThreatActor from './ThreatActor';
import ThreatActorKnowledge from './ThreatActorKnowledge';
import Loader from '../../../../components/Loader';
import FileManager from '../../common/files/FileManager';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import ThreatActorPopover from './ThreatActorPopover';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixDomainObjectIndicators from '../../observations/indicators/StixDomainObjectIndicators';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';

const subscription = graphql`
  subscription RootThreatActorSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on ThreatActor {
        ...ThreatActor_threatActor
        ...ThreatActorEditionContainer_threatActor
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...FilePendingViewer_entity
    }
  }
`;

const threatActorQuery = graphql`
  query RootThreatActorQuery($id: String!) {
    threatActor(id: $id) {
      id
      standard_id
      name
      aliases
      x_opencti_graph_data
      ...ThreatActor_threatActor
      ...ThreatActorKnowledge_threatActor
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...FilePendingViewer_entity
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
    settings {
      platform_enable_reference
    }
  }
`;

class RootThreatActor extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { threatActorId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: threatActorId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { threatActorId },
      },
    } = this.props;
    const link = `/dashboard/threats/threat_actors/${threatActorId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <Route path="/dashboard/threats/threat_actors/:threatActorId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'victimology',
              'threat_actors',
              'intrusion_sets',
              'campaigns',
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
        <QueryRenderer
          query={threatActorQuery}
          variables={{ id: threatActorId }}
          render={({ props }) => {
            if (props) {
              if (props.threatActor) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/threats/threat_actors/:threatActorId"
                      render={(routeProps) => (
                        <ThreatActor
                          {...routeProps}
                          threatActor={props.threatActor}
                          enableReferences={props.settings.platform_enable_reference?.includes(
                            'Threat-Actor',
                          )}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/threats/threat_actors/:threatActorId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/threats/threat_actors/${threatActorId}/knowledge/overview`}
                        />
                      )}
                    />
                    <Route
                      path="/dashboard/threats/threat_actors/:threatActorId/knowledge"
                      render={(routeProps) => (
                        <ThreatActorKnowledge
                          {...routeProps}
                          threatActor={props.threatActor}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/threats/threat_actors/:threatActorId/analysis"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.threatActor}
                            PopoverComponent={<ThreatActorPopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Threat-Actor',
                            )}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.threatActor
                            }
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/threats/threat_actors/:threatActorId/indicators"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.threatActor}
                            PopoverComponent={<ThreatActorPopover />}
                            variant="noaliases"
                          />
                          <StixDomainObjectIndicators
                            {...routeProps}
                            stixDomainObjectId={threatActorId}
                            stixDomainObjectLink={`/dashboard/threats/threat_actors/${threatActorId}/indicators`}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/threats/threat_actors/:threatActorId/indicators/relations/:relationId"
                      render={(routeProps) => (
                        <StixCoreRelationship
                          entityId={threatActorId}
                          {...routeProps}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/threats/threat_actors/:threatActorId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.threatActor}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Threat-Actor',
                            )}
                            PopoverComponent={<ThreatActorPopover />}
                          />
                          <FileManager
                            {...routeProps}
                            id={threatActorId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.threatActor}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/threats/threat_actors/:threatActorId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.threatActor}
                            PopoverComponent={<ThreatActorPopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Threat-Actor',
                            )}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={threatActorId}
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

RootThreatActor.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootThreatActor);
