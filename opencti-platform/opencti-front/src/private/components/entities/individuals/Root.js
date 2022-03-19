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
import Individual from './Individual';
import IndividualKnowledge from './IndividualKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import IndividualPopover from './IndividualPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import IndividualAnalysis from './IndividualAnalysis';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';

const subscription = graphql`
  subscription RootIndividualsSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Individual {
        ...Individual_individual
        ...IndividualEditionContainer_individual
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...FilePendingViewer_entity
    }
  }
`;

const individualQuery = graphql`
  query RootIndividualQuery($id: String!) {
    individual(id: $id) {
      id
      name
      x_opencti_aliases
      ...Individual_individual
      ...IndividualKnowledge_individual
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...FilePendingViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
    settings {
      platform_enable_reference
    }
  }
`;

class RootIndividual extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { individualId },
      },
    } = props;
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-individual-${individualId}`,
    );
    this.state = {
      viewAs: propOr('knowledge', 'viewAs', params),
    };
    this.sub = requestSubscription({
      subscription,
      variables: { id: individualId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  saveView() {
    const {
      match: {
        params: { individualId },
      },
    } = this.props;
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-individual-${individualId}`,
      this.state,
      true,
    );
  }

  handleChangeViewAs(event) {
    this.setState({ viewAs: event.target.value }, () => this.saveView());
  }

  render() {
    const {
      me,
      match: {
        params: { individualId },
      },
    } = this.props;
    const { viewAs } = this.state;
    const link = `/dashboard/entities/individuals/${individualId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <Route path="/dashboard/entities/individuals/:individualId/knowledge">
          {viewAs === 'knowledge' && (
            <StixCoreObjectKnowledgeBar
              stixCoreObjectLink={link}
              availableSections={[
                'organizations',
                'locations',
                'threat_actors',
                'intrusion_sets',
                'campaigns',
                'incidents',
                'malwares',
                'attack_patterns',
                'tools',
                'observables',
                'sightings',
              ]}
            />
          )}
        </Route>
        <QueryRenderer
          query={individualQuery}
          variables={{ id: individualId }}
          render={({ props }) => {
            if (props) {
              if (props.individual) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/entities/individuals/:individualId"
                      render={(routeProps) => (
                        <Individual
                          {...routeProps}
                          individual={props.individual}
                          viewAs={viewAs}
                          onViewAs={this.handleChangeViewAs.bind(this)}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/individuals/:individualId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/entities/individuals/${individualId}/knowledge/overview`}
                        />
                      )}
                    />
                    <Route
                      path="/dashboard/entities/individuals/:individualId/knowledge"
                      render={(routeProps) => (
                        <IndividualKnowledge
                          {...routeProps}
                          individual={props.individual}
                          viewAs={viewAs}
                          onViewAs={this.handleChangeViewAs.bind(this)}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/individuals/:individualId/analysis"
                      render={(routeProps) => (
                        <IndividualAnalysis
                          {...routeProps}
                          individual={props.individual}
                          viewAs={viewAs}
                          onViewAs={this.handleChangeViewAs.bind(this)}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/individuals/:individualId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.individual}
                            PopoverComponent={<IndividualPopover />}
                            onViewAs={this.handleChangeViewAs.bind(this)}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Individual',
                            )}
                          />
                          <FileManager
                            {...routeProps}
                            id={individualId}
                            connectorsImport={[]}
                            connectorsExport={props.connectorsForExport}
                            entity={props.individual}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/individuals/:individualId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.individual}
                            PopoverComponent={<IndividualPopover />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={individualId}
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

RootIndividual.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootIndividual);
