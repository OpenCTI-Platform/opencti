import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes, Link, Navigate } from 'react-router-dom';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import * as R from 'ramda';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import withRouter from '../../../../utils/compat_router/withRouter';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import AttackPattern from './AttackPattern';
import AttackPatternKnowledge from './AttackPatternKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import AttackPatternPopover from './AttackPatternPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import inject18n from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';

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
      stixCoreObjectsDistribution(field: "entity_type", operation: count) {
        label
        value
      }
      ...AttackPattern_attackPattern
      ...AttackPatternKnowledge_attackPattern
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
      <>
        <QueryRenderer
          query={attackPatternQuery}
          variables={{ id: attackPatternId }}
          render={({ props }) => {
            if (props) {
              if (props.attackPattern) {
                const { attackPattern } = props;
                const paddingRight = getPaddingRight(location.pathname, attackPattern.id, '/dashboard/techniques/attack_patterns');
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
                            stixCoreObjectsDistribution={attackPattern.stixCoreObjectsDistribution}
                          />
                        }
                      />
                    </Routes>
                    <div style={{ paddingRight }}>
                      <Breadcrumbs variant="object" elements={[
                        { label: t('Techniques') },
                        { label: t('Attack patterns'), link: '/dashboard/techniques/attack_patterns' },
                        { label: attackPattern.name, current: true },
                      ]}
                      />
                      <StixDomainObjectHeader
                        entityType="Attack-Pattern"
                        stixDomainObject={props.attackPattern}
                        PopoverComponent={<AttackPatternPopover />}
                      />
                      <Box
                        sx={{
                          borderBottom: 1,
                          borderColor: 'divider',
                          marginBottom: 4,
                        }}
                      >
                        <Tabs
                          value={getCurrentTab(location.pathname, attackPattern.id, '/dashboard/techniques/attack_patterns')}
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
                            to={`/dashboard/techniques/attack_patterns/${attackPattern.id}/content`}
                            value={`/dashboard/techniques/attack_patterns/${attackPattern.id}/content`}
                            label={t('Content')}
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
                            <AttackPattern attackPatternData={props.attackPattern} />
                        }
                        />
                        <Route
                          path="/knowledge"
                          element={
                            <Navigate to={`/dashboard/techniques/attack_patterns/${attackPatternId}/knowledge/overview`} replace={true} />
                        }
                        />
                        <Route
                          path="/knowledge/*"
                          element={
                            <AttackPatternKnowledge attackPattern={props.attackPattern} />
                        }
                        />
                        <Route
                          path="/content/*"
                          element={
                            <StixCoreObjectContentRoot
                              stixCoreObject={attackPattern}
                            />
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
                  </>
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

RootAttackPattern.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootAttackPattern);
