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
      x_opencti_graph_data
      ...IntrusionSet_intrusionSet
      ...IntrusionSetKnowledge_intrusionSet
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

class RootIntrusionSet extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { intrusionSetId },
      },
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
      match: {
        params: { intrusionSetId },
      },
    } = this.props;
    const link = `/dashboard/threats/intrusion_sets/${intrusionSetId}/knowledge`;
    return (
      <>
        <Route path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge">
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
              'observed_data',
            ]}
          />
        </Route>
        <QueryRenderer
          query={intrusionSetQuery}
          variables={{ id: intrusionSetId }}
          render={({ props }) => {
            if (props) {
              if (props.intrusionSet) {
                const { intrusionSet } = props;
                return (
                  <div
                    style={{
                      paddingRight: location.pathname.includes(
                        `/dashboard/threats/intrusion_sets/${intrusionSet.id}/knowledge`,
                      )
                        ? 200
                        : 0,
                    }}
                  >
                    <StixDomainObjectHeader
                      entityType="Intrusion-Set"
                      stixDomainObject={intrusionSet}
                      PopoverComponent={<IntrusionSetPopover />}
                      enableQuickSubscription={true}
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
                            `/dashboard/threats/intrusion_sets/${intrusionSet.id}/knowledge`,
                          )
                            ? `/dashboard/threats/intrusion_sets/${intrusionSet.id}/knowledge`
                            : location.pathname
                        }
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/threats/intrusion_sets/${intrusionSet.id}`}
                          value={`/dashboard/threats/intrusion_sets/${intrusionSet.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/knowledge`}
                          value={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/knowledge`}
                          label={t('Knowledge')}
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
                    </Box>
                    <Switch>
                      <Route
                        exact
                        path="/dashboard/threats/intrusion_sets/:intrusionSetId"
                        render={(routeProps) => (
                          <IntrusionSet
                            {...routeProps}
                            intrusionSet={props.intrusionSet}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge"
                        render={() => (
                          <Redirect
                            to={`/dashboard/threats/intrusion_sets/${intrusionSetId}/knowledge/overview`}
                          />
                        )}
                      />
                      <Route
                        path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge"
                        render={(routeProps) => (
                          <IntrusionSetKnowledge
                            {...routeProps}
                            intrusionSet={props.intrusionSet}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/threats/intrusion_sets/:intrusionSetId/analyses"
                        render={(routeProps) => (
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.intrusionSet
                            }
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/threats/intrusion_sets/:intrusionSetId/files"
                        render={(routeProps) => (
                          <FileManager
                            {...routeProps}
                            id={intrusionSetId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.intrusionSet}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/threats/intrusion_sets/:intrusionSetId/history"
                        render={(routeProps) => (
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={intrusionSetId}
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

RootIntrusionSet.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootIntrusionSet);
