import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { Route, Redirect, withRouter, Switch, Link } from 'react-router-dom';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import ThreatActorGroup from './ThreatActorGroup';
import ThreatActorGroupKnowledge from './ThreatActorGroupKnowledge';
import Loader from '../../../../components/Loader';
import FileManager from '../../common/files/FileManager';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import ThreatActorGroupPopover from './ThreatActorGroupPopover';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import inject18n from '../../../../components/i18n';

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
      ...PictureManagementViewer_entity
    }
  }
`;

const ThreatActorGroupQuery = graphql`
  query RootThreatActorGroupQuery($id: String!) {
    threatActorGroup(id: $id) {
      id
      standard_id
      entity_type
      name
      aliases
      x_opencti_graph_data
      ...ThreatActorGroup_ThreatActorGroup
      ...ThreatActorGroupKnowledge_ThreatActorGroup
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
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
      t,
      location,
      match: {
        params: { threatActorGroupId },
      },
    } = this.props;
    const link = `/dashboard/threats/threat_actors_group/${threatActorGroupId}/knowledge`;
    return (
      <>
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
              'indicators',
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
                const { threatActorGroup } = props;
                return (
                  <div
                    style={{
                      paddingRight: location.pathname.includes(
                        `/dashboard/threats/threat_actors_group/${threatActorGroup.id}/knowledge`,
                      )
                        ? 200
                        : 0,
                    }}
                  >
                    <StixDomainObjectHeader
                      entityType="Threat-Actor-Group"
                      stixDomainObject={threatActorGroup}
                      PopoverComponent={<ThreatActorGroupPopover />}
                      enableQuickSubscription={true}
                    />
                    <Box
                      sx={{
                        borderBottom: 1,
                        borderColor: 'divider',
                        marginBottom: 5,
                      }}
                    >
                      <Tabs
                        value={
                          location.pathname.includes(
                            `/dashboard/threats/threat_actors_group/${threatActorGroup.id}/knowledge`,
                          )
                            ? `/dashboard/threats/threat_actors_group/${threatActorGroup.id}/knowledge`
                            : location.pathname
                        }
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}`}
                          value={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/knowledge`}
                          value={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/analyses`}
                          value={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/analyses`}
                          label={t('Analyses')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/files`}
                          value={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/files`}
                          label={t('Data')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/history`}
                          value={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/history`}
                          label={t('Activity')}
                        />
                      </Tabs>
                    </Box>
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
                        path="/dashboard/threats/threat_actors_group/:threatActorGroupId/analyses"
                        render={(routeProps) => (
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.threatActorGroup
                            }
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/threats/threat_actors_group/:threatActorGroupId/files"
                        render={(routeProps) => (
                          <FileManager
                            {...routeProps}
                            id={threatActorGroupId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.threatActorGroup}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/threats/threat_actors_group/:threatActorGroupId/history"
                        render={(routeProps) => (
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={threatActorGroupId}
                          />
                        )}
                      />
                    </Switch>
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

RootThreatActorGroup.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootThreatActorGroup);
