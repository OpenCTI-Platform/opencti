import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Channel from './Channel';
import ChannelKnowledge from './ChannelKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import ChannelPopover from './ChannelPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixDomainObjectIndicators from '../../observations/indicators/StixDomainObjectIndicators';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';

const subscription = graphql`
  subscription RootChannelSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Channel {
        ...Channel_channel
        ...ChannelEditionContainer_channel
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...FilePendingViewer_entity
    }
  }
`;

const channelQuery = graphql`
  query RootChannelQuery($id: String!) {
    channel(id: $id) {
      id
      standard_id
      name
      aliases
      x_opencti_graph_data
      ...Channel_channel
      ...ChannelKnowledge_channel
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

class RootChannel extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { channelId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: channelId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { channelId },
      },
    } = this.props;
    const link = `/dashboard/arsenal/channels/${channelId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <Route path="/dashboard/arsenal/channels/:channelId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'victimology',
              'threat_actors',
              'intrusion_sets',
              'campaigns',
              'incidents',
              'malwares',
              'attack_patterns',
              'vulnerabilities',
              'observables',
              'sightings',
              'channels',
            ]}
          />
        </Route>
        <QueryRenderer
          query={channelQuery}
          variables={{ id: channelId }}
          render={({ props }) => {
            if (props) {
              if (props.channel) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/arsenal/channels/:channelId"
                      render={(routeProps) => (
                        <Channel
                          {...routeProps}
                          channel={props.channel}
                          enableReferences={props.settings.platform_enable_reference?.includes(
                            'Channel',
                          )}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/channels/:channelId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/arsenal/channels/${channelId}/knowledge/overview`}
                        />
                      )}
                    />
                    <Route
                      path="/dashboard/arsenal/channels/:channelId/knowledge"
                      render={(routeProps) => (
                        <ChannelKnowledge
                          {...routeProps}
                          channel={props.channel}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/channels/:channelId/analysis"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.channel}
                            PopoverComponent={<ChannelPopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Channel',
                            )}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.channel
                            }
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/channels/:channelId/indicators"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.channel}
                            PopoverComponent={<ChannelPopover />}
                            variant="noaliases"
                          />
                          <StixDomainObjectIndicators
                            {...routeProps}
                            stixDomainObjectId={channelId}
                            stixDomainObjectLink={`/dashboard/arsenal/channels/${channelId}/indicators`}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/channels/:channelId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.channel}
                            PopoverComponent={<ChannelPopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Channel',
                            )}
                          />
                          <FileManager
                            {...routeProps}
                            id={channelId}
                            connectorsImport={[]}
                            connectorsExport={props.connectorsForExport}
                            entity={props.channel}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/channels/:channelId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.channel}
                            PopoverComponent={<ChannelPopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Channel',
                            )}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={channelId}
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

RootChannel.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootChannel);
