import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
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
      match: {
        params: { intrusionSetId },
      },
    } = this.props;
    const link = `/dashboard/threats/intrusion_sets/${intrusionSetId}/knowledge`;
    return (
      <div>
        <TopBar />
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
                return (
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
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Intrusion-Set'}
                            stixDomainObject={props.intrusionSet}
                            PopoverComponent={<IntrusionSetPopover />}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.intrusionSet
                            }
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/threats/intrusion_sets/:intrusionSetId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Intrusion-Set'}
                            stixDomainObject={props.intrusionSet}
                            PopoverComponent={<IntrusionSetPopover />}
                          />
                          <FileManager
                            {...routeProps}
                            id={intrusionSetId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.intrusionSet}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/threats/intrusion_sets/:intrusionSetId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Intrusion-Set'}
                            stixDomainObject={props.intrusionSet}
                            PopoverComponent={<IntrusionSetPopover />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={intrusionSetId}
                          />
                        </React.Fragment>
                      )}
                    />
                  </Switch>
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

RootIntrusionSet.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default withRouter(RootIntrusionSet);
