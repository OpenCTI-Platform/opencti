import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch } from 'react-router-dom';
import { graphql } from 'react-relay';
import { propOr } from 'ramda';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
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
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-system-${systemId}`,
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
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-system-${systemId}`,
      this.state,
      true,
    );
  }

  handleChangeViewAs(event) {
    this.setState({ viewAs: event.target.value }, () => this.saveView());
  }

  render() {
    const {
      match: {
        params: { systemId },
      },
    } = this.props;
    const { viewAs } = this.state;
    const link = `/dashboard/entities/systems/${systemId}/knowledge`;
    return (
      <div>
        <TopBar />
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
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/entities/systems/:systemId"
                      render={(routeProps) => (
                        <System
                          {...routeProps}
                          system={props.system}
                          viewAs={viewAs}
                          onViewAs={this.handleChangeViewAs.bind(this)}
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
                          system={props.system}
                          viewAs={viewAs}
                          onViewAs={this.handleChangeViewAs.bind(this)}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/systems/:systemId/analyses"
                      render={(routeProps) => (
                        <SystemAnalysis
                          {...routeProps}
                          system={props.system}
                          viewAs={viewAs}
                          onViewAs={this.handleChangeViewAs.bind(this)}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/systems/:systemId/sightings"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'System'}
                            disableSharing={true}
                            stixDomainObject={props.system}
                            isOpenctiAlias={true}
                            PopoverComponent={<SystemPopover />}
                          />
                          <EntityStixSightingRelationships
                            entityId={props.system.id}
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
                      path="/dashboard/entities/systems/:systemId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'System'}
                            disableSharing={true}
                            stixDomainObject={props.system}
                            isOpenctiAlias={true}
                            PopoverComponent={<SystemPopover />}
                          />
                          <FileManager
                            {...routeProps}
                            id={systemId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.system}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/systems/:systemId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'System'}
                            disableSharing={true}
                            stixDomainObject={props.system}
                            isOpenctiAlias={true}
                            PopoverComponent={<SystemPopover />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={systemId}
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

RootSystem.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default withRouter(RootSystem);
