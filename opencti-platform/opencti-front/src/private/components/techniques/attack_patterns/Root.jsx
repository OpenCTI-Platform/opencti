import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes, Link, Navigate } from 'react-router-dom';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import * as R from 'ramda';
import withRouter from '../../../../utils/compat-router/withRouter';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import AttackPattern from './AttackPattern';
import AttackPatternKnowledge from './AttackPatternKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import inject18n from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import AttackPatternEdition from './AttackPatternEdition';
import CreateRelationshipButtonComponent from '../../common/menus/RelateComponent';
import RelateComponentContextProvider from '../../common/menus/RelateComponentProvider';

const subscription = graphql`
  subscription RootAttackPatternSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on AttackPattern {
        ...AttackPattern_attackPattern
        ...AttackPatternEditionContainer_attackPattern
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const attackPatternQuery = graphql`
  query RootAttackPatternQuery($id: String!) {
    attackPattern(id: $id) {
      id
      standard_id
      entity_type
      name
      aliases
      x_opencti_graph_data
      created_at
      updated_at
      ...AttackPattern_attackPattern
      ...AttackPatternKnowledge_attackPattern
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

class RootAttackPattern extends Component {
  constructor(props) {
    super(props);
    const {
      params: { attackPatternId },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: attackPatternId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      t,
      location,
      params: { attackPatternId },
    } = this.props;
    const link = `/dashboard/techniques/attack_patterns/${attackPatternId}/knowledge`;
    return (
      <RelateComponentContextProvider>
        <Routes>
          <Route
            path="/knowledge/*"
            element={
              <StixCoreObjectKnowledgeBar
                stixCoreObjectLink={link}
                availableSections={[
                  'victimology',
                  'threat_actors',
                  'intrusion_sets',
                  'campaigns',
                  'incidents',
                  'tools',
                  'vulnerabilities',
                  'malwares',
                  'indicators',
                  'observables',
                ]}
              />
            }
          />
        </Routes>
        <QueryRenderer
          query={attackPatternQuery}
          variables={{ id: attackPatternId }}
          render={({ props }) => {
            if (props) {
              if (props.attackPattern) {
                const { attackPattern } = props;
                return (
                  <div
                    style={{
                      paddingRight: location.pathname.includes(
                        `/dashboard/techniques/attack_patterns/${attackPattern.id}/knowledge`,
                      )
                        ? 200
                        : 0,
                    }}
                  >
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Techniques') },
                      { label: t('Attack patterns'), link: '/dashboard/techniques/attack_patterns' },
                      { label: attackPattern.name, current: true },
                    ]}
                    />
                    <StixDomainObjectHeader
                      entityType="AttackPattern"
                      disableSharing={true}
                      stixDomainObject={props.attackPattern}
                      EditComponent={<Security needs={[KNOWLEDGE_KNUPDATE]}>
                        <AttackPatternEdition
                          attackPatternId={attackPattern.id}
                        />
                      </Security>}
                      RelateComponent={<CreateRelationshipButtonComponent
                        id={attackPattern.id}
                        defaultStartTime={attackPattern.created_at}
                        defaultStopTime={attackPattern.updated_at}
                                       />}
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
                            `/dashboard/techniques/attack_patterns/${attackPattern.id}/knowledge`,
                          )
                            ? `/dashboard/techniques/attack_patterns/${attackPattern.id}/knowledge`
                            : location.pathname
                        }
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/techniques/attack_patterns/${attackPattern.id}`}
                          value={`/dashboard/techniques/attack_patterns/${attackPattern.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/techniques/attack_patterns/${attackPattern.id}/knowledge/overview`}
                          value={`/dashboard/techniques/attack_patterns/${attackPattern.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/techniques/attack_patterns/${attackPattern.id}/analyses`}
                          value={`/dashboard/techniques/attack_patterns/${attackPattern.id}/analyses`}
                          label={t('Analyses')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/techniques/attack_patterns/${attackPattern.id}/files`}
                          value={`/dashboard/techniques/attack_patterns/${attackPattern.id}/files`}
                          label={t('Data')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/techniques/attack_patterns/${attackPattern.id}/history`}
                          value={`/dashboard/techniques/attack_patterns/${attackPattern.id}/history`}
                          label={t('History')}
                        />
                      </Tabs>
                    </Box>
                    <Routes>
                      <Route
                        path="/"
                        element={
                          <AttackPattern attackPattern={props.attackPattern} />
                        }
                      />
                      <Route
                        path="/knowledge"
                        element={
                          <Navigate to={`/dashboard/techniques/attack_patterns/${attackPatternId}/knowledge/overview`} />
                        }
                      />
                      <Route
                        path="/knowledge/*"
                        element={
                          <AttackPatternKnowledge attackPattern={props.attackPattern} />
                        }
                      />
                      <Route
                        path="/analyses"
                        element={
                          <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={props.attackPattern} />
                        }
                      />
                      <Route
                        path="/files"
                        element={
                          <FileManager
                            id={attackPatternId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.attackPattern}
                          />
                        }
                      />
                      <Route
                        path="/history"
                        element={
                          <StixCoreObjectHistory stixCoreObjectId={attackPatternId} />
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
      </RelateComponentContextProvider>
    );
  }
}

RootAttackPattern.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootAttackPattern);
