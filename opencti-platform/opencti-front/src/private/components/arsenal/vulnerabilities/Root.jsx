import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes, Link, Navigate } from 'react-router-dom';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import withRouter from '../../../../utils/compat-router/withRouter';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import Vulnerability from './Vulnerability';
import VulnerabilityKnowledge from './VulnerabilityKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import VulnerabilityPopover from './VulnerabilityPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import inject18n from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';

const subscription = graphql`
  subscription RootVulnerabilitySubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Vulnerability {
        ...Vulnerability_vulnerability
        ...VulnerabilityEditionContainer_vulnerability
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const vulnerabilityQuery = graphql`
  query RootVulnerabilityQuery($id: String!) {
    vulnerability(id: $id) {
      id
      standard_id
      entity_type
      name
      x_opencti_aliases
      x_opencti_graph_data
      ...Vulnerability_vulnerability
      ...VulnerabilityKnowledge_vulnerability
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
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

class RootVulnerability extends Component {
  constructor(props) {
    super(props);
    const {
      params: { vulnerabilityId },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: vulnerabilityId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      t,
      location,
      params: { vulnerabilityId },
    } = this.props;
    const link = `/dashboard/arsenal/vulnerabilities/${vulnerabilityId}/knowledge`;
    return (
      <div>
        <Routes>
          <Route path="/knowledge/*" element={<StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'threats',
              'threat_actors',
              'intrusion_sets',
              'campaigns',
              'incidents',
              'malwares',
              'tools',
              'attack_patterns',
              'indicators',
              'observables',
              'sightings',
              'infrastructures',
            ]}
                                              />}
          >
          </Route>
        </Routes>
        <QueryRenderer
          query={vulnerabilityQuery}
          variables={{ id: vulnerabilityId }}
          render={({ props }) => {
            if (props) {
              if (props.vulnerability) {
                const { vulnerability } = props;
                const paddingRight = getPaddingRight(location.pathname, vulnerability.id, '/dashboard/arsenal/vulnerabilities');
                return (
                  <div style={{ paddingRight }}>
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Arsenal') },
                      { label: t('Vulnerabilities'), link: '/dashboard/arsenal/vulnerabilities' },
                      { label: vulnerability.name, current: true },
                    ]}
                    />
                    <StixDomainObjectHeader
                      entityType="Vulnerability"
                      stixDomainObject={vulnerability}
                      PopoverComponent={<VulnerabilityPopover />}
                      enableQuickSubscription={true}
                      isOpenctiAlias={true}
                    />
                    <Box
                      sx={{
                        borderBottom: 1,
                        borderColor: 'divider',
                        marginBottom: 4,
                      }}
                    >
                      <Tabs
                        value={getCurrentTab(location.pathname, vulnerability.id, '/dashboard/arsenal/vulnerabilities')}
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}`}
                          value={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/knowledge/overview`}
                          value={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/content`}
                          value={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/content`}
                          label={t('Content')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/analyses`}
                          value={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/analyses`}
                          label={t('Analyses')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/files`}
                          value={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/files`}
                          label={t('Data')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/history`}
                          value={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/history`}
                          label={t('History')}
                        />
                      </Tabs>
                    </Box>
                    <Routes>
                      <Route
                        path="/"
                        element={(
                          <Vulnerability
                            vulnerability={vulnerability}
                          />
                        )}
                      />
                      <Route
                        path="/knowledge"
                        element={(
                          <Navigate
                            replace={true}
                            to={`/dashboard/arsenal/vulnerabilities/${vulnerabilityId}/knowledge/overview`}
                          />
                        )}
                      />
                      <Route
                        path="/knowledge/*"
                        element={(
                          <VulnerabilityKnowledge
                            vulnerability={vulnerability}
                          />
                        )}
                      />
                      <Route
                        path="/content/*"
                        element={
                          <StixCoreObjectContentRoot
                            stixCoreObject={vulnerability}
                          />
                        }
                      />
                      <Route
                        path="/analyses"
                        element={(
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            stixDomainObjectOrStixCoreRelationship={vulnerability}
                          />
                        )}
                      />
                      <Route
                        path="/files"
                        element={(
                          <FileManager
                            id={vulnerabilityId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={vulnerability}
                          />
                        )}
                      />
                      <Route
                        path="/history"
                        element={(
                          <StixCoreObjectHistory
                            stixCoreObjectId={vulnerabilityId}
                          />
                        )}
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
      </div>
    );
  }
}

RootVulnerability.propTypes = {
  children: PropTypes.node,
  params: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootVulnerability);
