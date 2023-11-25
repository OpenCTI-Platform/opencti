import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch, Link } from 'react-router-dom';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import * as R from 'ramda';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
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
      match: {
        params: { attackPatternId },
      },
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
      match: {
        params: { attackPatternId },
      },
    } = this.props;
    const link = `/dashboard/techniques/attack_patterns/${attackPatternId}/knowledge`;
    return (
      <div>
        <Route path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge">
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
              'sightings',
              'indicators',
              'observables',
            ]}
          />
        </Route>
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
                    <StixDomainObjectHeader
                      entityType="AttackPattern"
                      disableSharing={true}
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
                          to={`/dashboard/techniques/attack_patterns/${attackPattern.id}/knowledge`}
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
                    <Switch>
                      <Route
                        exact
                        path="/dashboard/techniques/attack_patterns/:attackPatternId"
                        render={(routeProps) => (
                          <AttackPattern
                            {...routeProps}
                            attackPattern={props.attackPattern}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge"
                        render={() => (
                          <Redirect
                            to={`/dashboard/techniques/attack_patterns/${attackPatternId}/knowledge/overview`}
                          />
                        )}
                      />
                      <Route
                        path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge"
                        render={(routeProps) => (
                          <AttackPatternKnowledge
                            {...routeProps}
                            attackPattern={props.attackPattern}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/techniques/attack_patterns/:attackPatternId/analyses"
                        render={(routeProps) => (
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.attackPattern
                            }
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/techniques/attack_patterns/:attackPatternId/files"
                        render={(routeProps) => (
                          <FileManager
                            {...routeProps}
                            id={attackPatternId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.attackPattern}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/techniques/attack_patterns/:attackPatternId/history"
                        render={(routeProps) => (
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={attackPatternId}
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

RootAttackPattern.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootAttackPattern);
