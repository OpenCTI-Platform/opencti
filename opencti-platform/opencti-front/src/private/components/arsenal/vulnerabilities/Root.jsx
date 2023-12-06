import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes, Link, Navigate } from 'react-router-dom';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import withRouter from '../../../../utils/compat-router/withRouter';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import Vulnerability from './Vulnerability';
import VulnerabilityKnowledge from './VulnerabilityKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import inject18n from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import VulnerabilityEdition from './VulnerabilityEdition';
import CreateRelationshipButtonComponent from '../../common/menus/RelateComponent';
import RelateComponentContextProvider from '../../common/menus/RelateComponentProvider';

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
      created_at
      updated_at
      ...Vulnerability_vulnerability
      ...VulnerabilityKnowledge_vulnerability
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
      <RelateComponentContextProvider>
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
                return (
                  <div
                    style={{
                      paddingRight: location.pathname.includes(
                        `/dashboard/arsenal/vulnerabilities/${vulnerability.id}/knowledge`,
                      )
                        ? 200
                        : 0,
                    }}
                  >
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Arsenal') },
                      { label: t('Vulnerabilities'), link: '/dashboard/arsenal/vulnerabilities' },
                      { label: vulnerability.name, current: true },
                    ]}
                    />
                    <StixDomainObjectHeader
                      entityType="Vulnerability"
                      stixDomainObject={vulnerability}
                      EditComponent={<Security needs={[KNOWLEDGE_KNUPDATE]}>
                        <VulnerabilityEdition
                          vulnerabilityId={vulnerability.id}
                        />
                      </Security>}
                      RelateComponent={<CreateRelationshipButtonComponent
                        id={vulnerability.id}
                        defaultStartTime={vulnerability.created_at}
                        defaultStopTime={vulnerability.updated_at}
                                       />}
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
                        value={
                          location.pathname.includes(
                            `/dashboard/arsenal/vulnerabilities/${vulnerability.id}/knowledge`,
                          )
                            ? `/dashboard/arsenal/vulnerabilities/${vulnerability.id}/knowledge`
                            : location.pathname
                        }
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
      </RelateComponentContextProvider>
    );
  }
}

RootVulnerability.propTypes = {
  t: PropTypes.func,
  location: PropTypes.object,
  children: PropTypes.node,
  params: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootVulnerability);
