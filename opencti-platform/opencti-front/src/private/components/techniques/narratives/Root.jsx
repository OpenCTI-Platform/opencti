import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Narrative from './Narrative';
import NarrativeKnowledge from './NarrativeKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import NarrativePopover from './NarrativePopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';

const subscription = graphql`
  subscription RootNarrativeSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Narrative {
        ...Narrative_narrative
        ...NarrativeEditionContainer_narrative
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const narrativeQuery = graphql`
  query RootNarrativeQuery($id: String!) {
    narrative(id: $id) {
      id
      standard_id
      name
      aliases
      x_opencti_graph_data
      ...Narrative_narrative
      ...NarrativeKnowledge_narrative
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

class RootNarrative extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { narrativeId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: narrativeId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      match: {
        params: { narrativeId },
      },
    } = this.props;
    const link = `/dashboard/techniques/narratives/${narrativeId}/knowledge`;
    return (
      <div>
        <TopBar />
        <Route path="/dashboard/techniques/narratives/:narrativeId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'threat_actors',
              'intrusion_sets',
              'campaigns',
              'incidents',
              'channels',
              'observables',
              'sightings',
            ]}
          />
        </Route>
        <QueryRenderer
          query={narrativeQuery}
          variables={{ id: narrativeId }}
          render={({ props }) => {
            if (props) {
              if (props.narrative) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/techniques/narratives/:narrativeId"
                      render={(routeProps) => (
                        <Narrative
                          {...routeProps}
                          narrative={props.narrative}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/techniques/narratives/:narrativeId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/techniques/narratives/${narrativeId}/knowledge/overview`}
                        />
                      )}
                    />
                    <Route
                      path="/dashboard/techniques/narratives/:narrativeId/knowledge"
                      render={(routeProps) => (
                        <NarrativeKnowledge
                          {...routeProps}
                          narrative={props.narrative}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/techniques/narratives/:narrativeId/analyses"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Narrative'}
                            stixDomainObject={props.narrative}
                            PopoverComponent={<NarrativePopover />}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.narrative
                            }
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/techniques/narratives/:narrativeId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Narrative'}
                            stixDomainObject={props.narrative}
                            PopoverComponent={<NarrativePopover />}
                          />
                          <FileManager
                            {...routeProps}
                            id={narrativeId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.narrative}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/techniques/narratives/:narrativeId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Narrative'}
                            stixDomainObject={props.narrative}
                            PopoverComponent={<NarrativePopover />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={narrativeId}
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

RootNarrative.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default withRouter(RootNarrative);
