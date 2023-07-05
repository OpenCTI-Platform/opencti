import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import ThreatActorGroup from './ThreatActorGroup';
import ThreatActorGroupKnowledge from './ThreatActorGroupKnowledge';
import Loader from '../../../../components/Loader';
import FileManager from '../../common/files/FileManager';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import ThreatActorGroupPopover from './ThreatActorGroupPopover';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixDomainObjectIndicators from '../../observations/indicators/StixDomainObjectIndicators';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';

const subscription = graphql`
  subscription RootThreatActorsGroupSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on ThreatActor {
        ...ThreatActorGroup_ThreatActorGroup
        ...ThreatActorGroupEditionContainer_ThreatActorGroup
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const ThreatActorGroupQuery = graphql`
  query RootThreatActorGroupQuery($id: String!) {
    threatActorGroup(id: $id) {
      id
      standard_id
      name
      aliases
      x_opencti_graph_data
      ...ThreatActorGroup_ThreatActorGroup
      ...ThreatActorGroupKnowledge_ThreatActorGroup
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

class RootThreatActorGroup extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { threatActorGroupId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: threatActorGroupId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      match: {
        params: { threatActorGroupId },
      },
    } = this.props;
    const link = `/dashboard/threats/threat_actors_group/${threatActorGroupId}/knowledge`;
    return (
      <div>
        <TopBar />
        <Route path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge">
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
              'channels',
              'narratives',
              'tools',
              'vulnerabilities',
              'observables',
              'infrastructures',
              'sightings',
            ]}
          />
        </Route>
        <QueryRenderer
          query={ThreatActorGroupQuery}
          variables={{ id: threatActorGroupId }}
          render={({ props }) => {
            if (props) {
              if (props.threatActorGroup) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/threats/threat_actors_group/:threatActorGroupId"
                      render={(routeProps) => (
                        <ThreatActorGroup
                          {...routeProps}
                          threatActorGroup={props.threatActorGroup}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/threats/threat_actors_group/${threatActorGroupId}/knowledge/overview`}
                        />
                      )}
                    />
                    <Route
                      path="/dashboard/threats/threat_actors_group/:threatActorGroupId/knowledge"
                      render={(routeProps) => (
                        <ThreatActorGroupKnowledge
                          {...routeProps}
                          threatActorGroup={props.threatActorGroup}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/threats/threat_actors_group/:threatActorGroupId/analysis"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Threat-Actor-Group'}
                            stixDomainObject={props.threatActorGroup}
                            PopoverComponent={<ThreatActorGroupPopover />}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.threatActorGroup
                            }
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/threats/threat_actors_group/:threatActorGroupId/indicators"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Threat-Actor-Group'}
                            stixDomainObject={props.threatActorGroup}
                            PopoverComponent={<ThreatActorGroupPopover />}
                            disableSharing={true}
                          />
                          <StixDomainObjectIndicators
                            {...routeProps}
                            stixDomainObjectId={threatActorGroupId}
                            stixDomainObjectLink={`/dashboard/threats/threat_actors_group/${threatActorGroupId}/indicators`}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/threats/threat_actors_group/:threatActorGroupId/indicators/relations/:relationId"
                      render={(routeProps) => (
                        <StixCoreRelationship
                          entityId={threatActorGroupId}
                          {...routeProps}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/threats/threat_actors_group/:threatActorGroupId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Threat-Actor-Group'}
                            stixDomainObject={props.threatActorGroup}
                            PopoverComponent={<ThreatActorGroupPopover />}
                          />
                          <FileManager
                            {...routeProps}
                            id={threatActorGroupId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.threatActorGroup}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/threats/threat_actors_group/:threatActorGroupId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Threat-Actor-Group'}
                            stixDomainObject={props.threatActorGroup}
                            PopoverComponent={<ThreatActorGroupPopover />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={threatActorGroupId}
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

RootThreatActorGroup.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default withRouter(RootThreatActorGroup);
