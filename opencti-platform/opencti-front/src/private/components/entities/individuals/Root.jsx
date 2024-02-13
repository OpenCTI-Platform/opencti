import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch, Link } from 'react-router-dom';
import { graphql } from 'react-relay';
import { propOr } from 'ramda';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import Individual from './Individual';
import IndividualKnowledge from './IndividualKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import IndividualPopover from './IndividualPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import IndividualAnalysis from './IndividualAnalysis';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import inject18n from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';

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
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
    }
  }
`;

const individualQuery = graphql`
  query RootIndividualQuery($id: String!) {
    individual(id: $id) {
      id
      entity_type
      name
      x_opencti_aliases
      ...Individual_individual
      ...IndividualKnowledge_individual
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

class RootIndividual extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { individualId },
      },
    } = props;
    const LOCAL_STORAGE_KEY = `individual-${individualId}`;
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
    const LOCAL_STORAGE_KEY = `individual-${individualId}`;
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
        params: { individualId },
      },
    } = this.props;
    const { viewAs } = this.state;
    const link = `/dashboard/entities/individuals/${individualId}/knowledge`;
    return (
      <>
        <Route path="/dashboard/entities/individuals/:individualId/knowledge">
          {viewAs === 'knowledge' && (
            <StixCoreObjectKnowledgeBar
              stixCoreObjectLink={link}
              availableSections={[
                'organizations',
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
          )}
        </Route>
        <QueryRenderer
          query={individualQuery}
          variables={{ id: individualId }}
          render={({ props }) => {
            if (props) {
              if (props.individual) {
                const { individual } = props;
                return (
                  <div
                    style={{
                      paddingRight: location.pathname.includes(
                        `/dashboard/entities/individuals/${individual.id}/knowledge`,
                      )
                        ? 200
                        : 0,
                    }}
                  >
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Entities') },
                      { label: t('Individuals'), link: '/dashboard/entities/individuals' },
                      { label: individual.name, current: true },
                    ]}
                    />
                    <StixDomainObjectHeader
                      entityType="Individual"
                      disableSharing={true}
                      stixDomainObject={individual}
                      isOpenctiAlias={true}
                      enableQuickSubscription={true}
                      PopoverComponent={<IndividualPopover />}
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
                            `/dashboard/entities/individuals/${individual.id}/knowledge`,
                          )
                            ? `/dashboard/entities/individuals/${individual.id}/knowledge`
                            : location.pathname
                        }
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/individuals/${individual.id}`}
                          value={`/dashboard/entities/individuals/${individual.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/individuals/${individual.id}/knowledge`}
                          value={`/dashboard/entities/individuals/${individual.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/individuals/${individual.id}/analyses`}
                          value={`/dashboard/entities/individuals/${individual.id}/analyses`}
                          label={t('Analyses')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/individuals/${individual.id}/sightings`}
                          value={`/dashboard/entities/individuals/${individual.id}/sightings`}
                          label={t('Sightings')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/individuals/${individual.id}/files`}
                          value={`/dashboard/entities/individuals/${individual.id}/files`}
                          label={t('Data')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/individuals/${individual.id}/history`}
                          value={`/dashboard/entities/individuals/${individual.id}/history`}
                          label={t('History')}
                        />
                      </Tabs>
                    </Box>
                    <Switch>
                      <Route
                        exact
                        path="/dashboard/entities/individuals/:individualId"
                        render={(routeProps) => (
                          <Individual
                            {...routeProps}
                            individual={individual}
                            viewAs={viewAs}
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
                            individual={individual}
                            viewAs={viewAs}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/entities/individuals/:individualId/analyses"
                        render={(routeProps) => (
                          <IndividualAnalysis
                            {...routeProps}
                            individual={individual}
                            viewAs={viewAs}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/entities/individuals/:individualId/sightings"
                        render={(routeProps) => (
                          <EntityStixSightingRelationships
                            entityId={individual.id}
                            entityLink={link}
                            noPadding={true}
                            isTo={true}
                            {...routeProps}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/entities/individuals/:individualId/files"
                        render={(routeProps) => (
                          <FileManager
                            {...routeProps}
                            id={individualId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={individual}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/entities/individuals/:individualId/history"
                        render={(routeProps) => (
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={individualId}
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

RootIndividual.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootIndividual);
