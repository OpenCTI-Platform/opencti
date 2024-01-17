import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch, Link } from 'react-router-dom';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
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
import BreadcrumbHeader from '../../../../components/BreadcrumbHeader';

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
      match: {
        params: { vulnerabilityId },
      },
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
      match: {
        params: { vulnerabilityId },
      },
    } = this.props;
    const link = `/dashboard/arsenal/vulnerabilities/${vulnerabilityId}/knowledge`;
    const path = [
      {
        text: t('Arsenal'),
      },
      {
        text: t('Vulnerabilities'),
        link: '/dashboard/arsenal/vulnerabilities',
      },
    ];
    return (
      <div>
        <Route path="/dashboard/arsenal/vulnerabilities/:vulnerabilityId/knowledge">
          <StixCoreObjectKnowledgeBar
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
          />
        </Route>
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
                    <BreadcrumbHeader path={path}>
                      <StixDomainObjectHeader
                        entityType="Vulnerability"
                        stixDomainObject={vulnerability}
                        PopoverComponent={<VulnerabilityPopover />}
                        enableQuickSubscription={true}
                        isOpenctiAlias={true}
                      />
                    </BreadcrumbHeader>
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
                          to={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/knowledge`}
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
                    <Switch>
                      <Route
                        exact
                        path="/dashboard/arsenal/vulnerabilities/:vulnerabilityId"
                        render={(routeProps) => (
                          <Vulnerability
                            {...routeProps}
                            vulnerability={props.vulnerability}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/arsenal/vulnerabilities/:vulnerabilityId/knowledge"
                        render={() => (
                          <Redirect
                            to={`/dashboard/arsenal/vulnerabilities/${vulnerabilityId}/knowledge/overview`}
                          />
                        )}
                      />
                      <Route
                        path="/dashboard/arsenal/vulnerabilities/:vulnerabilityId/knowledge"
                        render={(routeProps) => (
                          <VulnerabilityKnowledge
                            {...routeProps}
                            vulnerability={props.vulnerability}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/arsenal/vulnerabilities/:vulnerabilityId/analyses"
                        render={(routeProps) => (
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.vulnerability
                            }
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/arsenal/vulnerabilities/:vulnerabilityId/files"
                        render={(routeProps) => (
                          <FileManager
                            {...routeProps}
                            id={vulnerabilityId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.vulnerability}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/arsenal/vulnerabilities/:vulnerabilityId/history"
                        render={(routeProps) => (
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={vulnerabilityId}
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
      </div>
    );
  }
}

RootVulnerability.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootVulnerability);
