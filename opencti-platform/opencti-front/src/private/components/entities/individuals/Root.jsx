import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes, Link, Navigate } from 'react-router-dom';
import { graphql } from 'react-relay';
import { propOr } from 'ramda';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import withRouter from '../../../../utils/compat-router/withRouter';
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
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';

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
      ...StixCoreObjectContent_stixCoreObject
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
      params: { individualId },
    } = props;
    const LOCAL_STORAGE_KEY = `individual-${individualId}`;
    const params = buildViewParamsFromUrlAndStorage(
      props.navigate,
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
      params: { individualId },
    } = this.props;
    const LOCAL_STORAGE_KEY = `individual-${individualId}`;
    saveViewParameters(
      this.props.navigate,
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
      params: { individualId },
    } = this.props;
    const { viewAs } = this.state;
    const link = `/dashboard/entities/individuals/${individualId}/knowledge`;

    return (
      <>
        <Routes>
          <Route
            path="/knowledge/*"
            element={viewAs === 'knowledge' && (
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
            />)}
          >
          </Route>
        </Routes>
        <QueryRenderer
          query={individualQuery}
          variables={{ id: individualId }}
          render={({ props }) => {
            if (props) {
              if (props.individual) {
                const { individual } = props;
                let paddingRight = 0;
                if (viewAs === 'knowledge') {
                  paddingRight = getPaddingRight(location.pathname, individual.id, '/dashboard/entities/individuals');
                }
                return (
                  <div style={{ paddingRight }}>
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
                        value={getCurrentTab(location.pathname, individual.id, '/dashboard/entities/individuals')}
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/individuals/${individual.id}`}
                          value={`/dashboard/entities/individuals/${individual.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/individuals/${individual.id}/knowledge/overview`}
                          value={`/dashboard/entities/individuals/${individual.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/individuals/${individual.id}/content`}
                          value={`/dashboard/entities/individuals/${individual.id}/content`}
                          label={t('Content')}
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
                    <Routes>
                      <Route
                        path="/"
                        element={
                          <Individual
                            individual={individual}
                            viewAs={viewAs}
                          />
                        }
                      />
                      <Route
                        path="/knowledge"
                        element={
                          <Navigate
                            replace={true}
                            to={`/dashboard/entities/individuals/${individualId}/knowledge/overview`}
                          />
                        }
                      />
                      <Route
                        path="/knowledge/*"
                        element={
                          <IndividualKnowledge
                            individual={individual}
                            viewAs={viewAs}
                          />
                        }
                      />
                      <Route
                        path="/content/*"
                        element={
                          <StixCoreObjectContentRoot
                            stixCoreObject={individual}
                          />
                        }
                      />
                      <Route
                        path="/analyses"
                        element={
                          <IndividualAnalysis
                            individual={individual}
                            viewAs={viewAs}
                          />
                        }
                      />
                      <Route
                        path="/sightings"
                        element={
                          <EntityStixSightingRelationships
                            entityId={individual.id}
                            entityLink={link}
                            noPadding={true}
                            isTo={true}
                          />
                        }
                      />
                      <Route
                        path="/files"
                        element={
                          <FileManager
                            id={individualId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={individual}
                          />
                        }
                      />
                      <Route
                        path="/history"
                        element={
                          <StixCoreObjectHistory
                            stixCoreObjectId={individualId}
                          />
                        }
                      />
                    </Routes>
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
  params: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootIndividual);
