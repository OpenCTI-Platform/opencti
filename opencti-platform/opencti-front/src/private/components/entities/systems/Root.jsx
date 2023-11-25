import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch, Link } from 'react-router-dom';
import { graphql } from 'react-relay';
import { propOr } from 'ramda';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import System from './System';
import SystemKnowledge from './SystemKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import SystemPopover from './SystemPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import SystemAnalysis from './SystemAnalysis';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import inject18n from '../../../../components/i18n';

const subscription = graphql`
  subscription RootSystemsSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on System {
        ...System_system
        ...SystemEditionContainer_system
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const systemQuery = graphql`
  query RootSystemQuery($id: String!) {
    system(id: $id) {
      id
      entity_type
      name
      x_opencti_aliases
      ...System_system
      ...SystemKnowledge_system
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

class RootSystem extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { systemId },
      },
    } = props;
    const LOCAL_STORAGE_KEY = `system-${systemId}`;
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      LOCAL_STORAGE_KEY,
    );
    this.state = {
      viewAs: propOr('knowledge', 'viewAs', params),
    };
    this.sub = requestSubscription({
      subscription,
      variables: { id: systemId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  saveView() {
    const {
      match: {
        params: { systemId },
      },
    } = this.props;
    const LOCAL_STORAGE_KEY = `system-${systemId}`;
    saveViewParameters(
      this.props.history,
      this.props.location,
      LOCAL_STORAGE_KEY,
      this.state,
      true,
    );
  }

  handleChangeViewAs(event) {
    this.setState({ viewAs: event.target.value }, () => this.saveView());
  }

  render() {
    const {
      t,
      location,
      match: {
        params: { systemId },
      },
    } = this.props;
    const { viewAs } = this.state;
    const link = `/dashboard/entities/systems/${systemId}/knowledge`;
    return (
      <>
        <Route path="/dashboard/entities/systems/:systemId/knowledge">
          {viewAs === 'knowledge' && (
            <StixCoreObjectKnowledgeBar
              stixCoreObjectLink={link}
              availableSections={[
                'systems',
                'systems',
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
          )}
        </Route>
        <QueryRenderer
          query={systemQuery}
          variables={{ id: systemId }}
          render={({ props }) => {
            if (props) {
              if (props.system) {
                const { system } = props;
                return (
                  <div
                    style={{
                      paddingRight: location.pathname.includes(
                        `/dashboard/threats/campaigns/${system.id}/knowledge`,
                      )
                        ? 200
                        : 0,
                    }}
                  >
                    <StixDomainObjectHeader
                      entityType="System"
                      disableSharing={true}
                      stixDomainObject={system}
                      isOpenctiAlias={true}
                      enableQuickSubscription={true}
                      PopoverComponent={<SystemPopover />}
                      onViewAs={this.handleChangeViewAs.bind(this)}
                      viewAs={viewAs}
                    />
                    <Box
                      sx={{
                        borderBottom: 1,
                        borderColor: 'divider',
                        marginBottom: 4,
                      }}
                    >
                      <Tabs
                        value={
                          location.pathname.includes(
                            `/dashboard/entities/systems/${system.id}/knowledge`,
                          )
                            ? `/dashboard/entities/systems/${system.id}/knowledge`
                            : location.pathname
                        }
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/systems/${system.id}`}
                          value={`/dashboard/entities/systems/${system.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/systems/${system.id}/knowledge`}
                          value={`/dashboard/entities/systems/${system.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/systems/${system.id}/analyses`}
                          value={`/dashboard/entities/systems/${system.id}/analyses`}
                          label={t('Analyses')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/systems/${system.id}/files`}
                          value={`/dashboard/entities/systems/${system.id}/files`}
                          label={t('Data')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/systems/${system.id}/history`}
                          value={`/dashboard/entities/systems/${system.id}/history`}
                          label={t('History')}
                        />
                      </Tabs>
                    </Box>
                    <Switch>
                      <Route
                        exact
                        path="/dashboard/entities/systems/:systemId"
                        render={(routeProps) => (
                          <System
                            {...routeProps}
                            system={system}
                            viewAs={viewAs}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/entities/systems/:systemId/knowledge"
                        render={() => (
                          <Redirect
                            to={`/dashboard/entities/systems/${systemId}/knowledge/overview`}
                          />
                        )}
                      />
                      <Route
                        path="/dashboard/entities/systems/:systemId/knowledge"
                        render={(routeProps) => (
                          <SystemKnowledge
                            {...routeProps}
                            system={system}
                            viewAs={viewAs}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/entities/systems/:systemId/analyses"
                        render={(routeProps) => (
                          <SystemAnalysis
                            {...routeProps}
                            system={system}
                            viewAs={viewAs}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/entities/systems/:systemId/sightings"
                        render={(routeProps) => (
                          <EntityStixSightingRelationships
                            entityId={system.id}
                            entityLink={link}
                            noPadding={true}
                            isTo={true}
                            {...routeProps}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/entities/systems/:systemId/files"
                        render={(routeProps) => (
                          <FileManager
                            {...routeProps}
                            id={systemId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={system}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/entities/systems/:systemId/history"
                        render={(routeProps) => (
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={systemId}
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

RootSystem.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootSystem);
