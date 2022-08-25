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
import StixDomainObjectIndicators from '../../observations/indicators/StixDomainObjectIndicators';
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
      ...FilePendingViewer_entity
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
      ...FilePendingViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
    settings {
      platform_enable_reference
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
      me,
      match: {
        params: { narrativeId },
      },
    } = this.props;
    const link = `/dashboard/arsenal/narratives/${narrativeId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <Route path="/dashboard/arsenal/narratives/:narrativeId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'threat_actors',
              'intrusion_sets',
              'campaigns',
              'incidents',
              'malwares',
              'channels',
              'attack_patterns',
              'vulnerabilities',
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
                      path="/dashboard/arsenal/narratives/:narrativeId"
                      render={(routeProps) => (
                        <Narrative
                          {...routeProps}
                          narrative={props.narrative}
                          enableReferences={props.settings.platform_enable_reference?.includes(
                            'Narrative',
                          )}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/narratives/:narrativeId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/arsenal/narratives/${narrativeId}/knowledge/overview`}
                        />
                      )}
                    />
                    <Route
                      path="/dashboard/arsenal/narratives/:narrativeId/knowledge"
                      render={(routeProps) => (
                        <NarrativeKnowledge
                          {...routeProps}
                          narrative={props.narrative}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/narratives/:narrativeId/analysis"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.narrative}
                            PopoverComponent={<NarrativePopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Narrative',
                            )}
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
                      path="/dashboard/arsenal/narratives/:narrativeId/indicators"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.narrative}
                            PopoverComponent={<NarrativePopover />}
                            variant="noaliases"
                          />
                          <StixDomainObjectIndicators
                            {...routeProps}
                            stixDomainObjectId={narrativeId}
                            stixDomainObjectLink={`/dashboard/arsenal/narratives/${narrativeId}/indicators`}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/narratives/:narrativeId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.narrative}
                            PopoverComponent={<NarrativePopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Narrative',
                            )}
                          />
                          <FileManager
                            {...routeProps}
                            id={narrativeId}
                            connectorsImport={[]}
                            connectorsExport={props.connectorsForExport}
                            entity={props.narrative}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/narratives/:narrativeId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.narrative}
                            PopoverComponent={<NarrativePopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Narrative',
                            )}
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
  me: PropTypes.object,
};

export default withRouter(RootNarrative);
