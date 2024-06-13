import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes, Link, Navigate } from 'react-router-dom';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import * as R from 'ramda';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import StixCoreObjectSimulationResult from '../../common/stix_core_objects/StixCoreObjectSimulationResult';
import withRouter from '../../../../utils/compat-router/withRouter';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import IntrusionSet from './IntrusionSet';
import IntrusionSetKnowledge from './IntrusionSetKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import IntrusionSetPopover from './IntrusionSetPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import inject18n from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';

const subscription = graphql`
  subscription RootIntrusionSetSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on IntrusionSet {
        ...IntrusionSet_intrusionSet
        ...IntrusionSetEditionContainer_intrusionSet
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
    }
  }
`;

const intrusionSetQuery = graphql`
  query RootIntrusionSetQuery($id: String!) {
    intrusionSet(id: $id) {
      id
      standard_id
      entity_type
      name
      aliases
      objectMarking {
          id
      } 
      x_opencti_graph_data
      ...IntrusionSet_intrusionSet
      ...IntrusionSetKnowledge_intrusionSet
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

class RootIntrusionSet extends Component {
  constructor(props) {
    super(props);
    const {
      params: { intrusionSetId },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: intrusionSetId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      t,
      location,
      params: { intrusionSetId },
    } = this.props;

    const link = `/dashboard/threats/intrusion_sets/${intrusionSetId}/knowledge`;
    return (
      <>
        <Routes>
          <Route
            path="/knowledge/*"
            element={
              <StixCoreObjectKnowledgeBar
                stixCoreObjectLink={link}
                availableSections={[
                  'victimology',
                  'attribution',
                  'campaigns',
                  'incidents',
                  'malwares',
                  'attack_patterns',
                  'tools',
                  'channels',
                  'narratives',
                  'vulnerabilities',
                  'indicators',
                  'observables',
                  'infrastructures',
                  'sightings',
                ]}
              />
            }
          />
        </Routes>
        <QueryRenderer
          query={intrusionSetQuery}
          variables={{ id: intrusionSetId }}
          render={({ props }) => {
            if (props) {
              if (props.intrusionSet) {
                const { intrusionSet } = props;
                const isOverview = location.pathname === `/dashboard/threats/intrusion_sets/${intrusionSet.id}`;
                const paddingRight = getPaddingRight(location.pathname, intrusionSet.id, '/dashboard/threats/intrusion_sets');
                return (
                  <div style={{ paddingRight }} data-testid="intrusionSet-details-page">
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Threats') },
                      { label: t('Intrusion sets'), link: '/dashboard/threats/intrusion_sets' },
                      { label: intrusionSet.name, current: true },
                    ]}
                    />
                    <StixDomainObjectHeader
                      entityType="Intrusion-Set"
                      stixDomainObject={intrusionSet}
                      PopoverComponent={<IntrusionSetPopover />}
                      enableQuickSubscription={true}
                      enableAskAi={true}
                    />
                    <Box
                      sx={{
                        borderBottom: 1,
                        borderColor: 'divider',
                        marginBottom: 4,
                      }}
                    >
                      <Tabs
                        value={getCurrentTab(location.pathname, intrusionSet.id, '/dashboard/threats/intrusion_sets')}
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/threats/intrusion_sets/${intrusionSet.id}`}
                          value={`/dashboard/threats/intrusion_sets/${intrusionSet.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/knowledge/overview`}
                          value={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/content`}
                          value={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/content`}
                          label={t('Content')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/analyses`}
                          value={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/analyses`}
                          label={t('Analyses')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/files`}
                          value={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/files`}
                          label={t('Data')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/history`}
                          value={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/history`}
                          label={t('History')}
                        />
                      </Tabs>
                      {isOverview && (
                        <StixCoreObjectSimulationResult id={intrusionSet.id} type="threat" />
                      )}
                    </Box>
                    <Routes>
                      <Route
                        path="/"
                        element={
                          <IntrusionSet intrusionSet={props.intrusionSet} />
                        }
                      />
                      <Route
                        path="/knowledge"
                        element={
                          <Navigate to={`/dashboard/threats/intrusion_sets/${intrusionSetId}/knowledge/overview`} replace={true} />
                        }
                      />
                      <Route
                        path="/knowledge/*"
                        element={
                          <div data-testid="instrusionSet-knowledge">
                            <IntrusionSetKnowledge intrusionSet={props.intrusionSet} />
                          </div>
                        }
                      />
                      <Route
                        path="/content/*"
                        element={
                          <StixCoreObjectContentRoot
                            stixCoreObject={intrusionSet}
                          />
                        }
                      />
                      <Route
                        path="/analyses"
                        element={
                          <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={props.intrusionSet} />
                        }
                      />
                      <Route
                        path="/files"
                        element={
                          <FileManager
                            id={intrusionSetId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.intrusionSet}
                          />
                        }
                      />
                      <Route
                        path="/history"
                        element={
                          <StixCoreObjectHistory stixCoreObjectId={intrusionSetId} />
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

RootIntrusionSet.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootIntrusionSet);
