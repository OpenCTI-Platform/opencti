import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link, Redirect, Route, Switch, withRouter } from 'react-router-dom';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import * as R from 'ramda';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import Channel from './Channel';
import ChannelKnowledge from './ChannelKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import ChannelPopover from './ChannelPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import inject18n from '../../../../components/i18n';

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
      ...WorkbenchFileViewer_entity
    }
  }
`;

const channelQuery = graphql`
  query RootChannelQuery($id: String!) {
    channel(id: $id) {
      id
      standard_id
      entity_type
      name
      aliases
      x_opencti_graph_data
      ...Channel_channel
      ...ChannelKnowledge_channel
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
      t,
      location,
      match: {
        params: { channelId },
      },
    } = this.props;
    const link = `/dashboard/arsenal/channels/${channelId}/knowledge`;
    return (
      <div>
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
                const { channel } = props;
                return (
                  <div
                    style={{
                      paddingRight: location.pathname.includes(
                        `/dashboard/arsenal/channels/${channel.id}/knowledge`,
                      )
                        ? 200
                        : 0,
                    }}
                  >
                    <StixDomainObjectHeader
                      entityType="Channel"
                      stixDomainObject={channel}
                      PopoverComponent={<ChannelPopover />}
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
                            `/dashboard/arsenal/channels/${channel.id}/knowledge`,
                          )
                            ? `/dashboard/arsenal/channels/${channel.id}/knowledge`
                            : location.pathname
                        }
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/arsenal/channels/${channel.id}`}
                          value={`/dashboard/arsenal/channels/${channel.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/arsenal/channels/${channel.id}/knowledge`}
                          value={`/dashboard/arsenal/channels/${channel.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/arsenal/channels/${channel.id}/analyses`}
                          value={`/dashboard/arsenal/channels/${channel.id}/analyses`}
                          label={t('Analyses')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/arsenal/channels/${channel.id}/files`}
                          value={`/dashboard/arsenal/channels/${channel.id}/files`}
                          label={t('Data')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/arsenal/channels/${channel.id}/history`}
                          value={`/dashboard/arsenal/channels/${channel.id}/history`}
                          label={t('History')}
                        />
                      </Tabs>
                    </Box>
                    <Switch>
                      <Route
                        exact
                        path="/dashboard/arsenal/channels/:channelId"
                        render={(routeProps) => (
                          <Channel {...routeProps} channel={props.channel} />
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
                        path="/dashboard/arsenal/channels/:channelId/analyses"
                        render={(routeProps) => (
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.channel
                            }
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/arsenal/channels/:channelId/files"
                        render={(routeProps) => (
                          <FileManager
                            {...routeProps}
                            id={channelId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.channel}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/arsenal/channels/:channelId/history"
                        render={(routeProps) => (
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={channelId}
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

RootChannel.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootChannel);
