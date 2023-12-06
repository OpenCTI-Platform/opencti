import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link, Navigate, Route, Routes } from 'react-router-dom';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import * as R from 'ramda';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import Channel from './Channel';
import ChannelKnowledge from './ChannelKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import inject18n from '../../../../components/i18n';
import withRouter from '../../../../utils/compat-router/withRouter';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import ChannelEdition from './ChannelEdition';
import CreateRelationshipButtonComponent from '../../common/menus/RelateComponent';
import RelateComponentContextProvider from '../../common/menus/RelateComponentProvider';

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
      created_at
      updated_at
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
      params: { channelId },
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
      params: { channelId },
    } = this.props;
    const link = `/dashboard/arsenal/channels/${channelId}/knowledge`;
    return (
      <RelateComponentContextProvider>
        <Routes>
          <Route path="/knowledge/*"
            element= {<StixCoreObjectKnowledgeBar
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
                      />}
          ></Route>
        </Routes>
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
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Arsenal') },
                      { label: t('Channels'), link: '/dashboard/arsenal/channels' },
                      { label: channel.name, current: true },
                    ]}
                    />
                    <StixDomainObjectHeader
                      entityType="Channel"
                      stixDomainObject={channel}
                      EditComponent={<Security needs={[KNOWLEDGE_KNUPDATE]}>
                        <ChannelEdition
                          channelId={channel.id}
                        />
                      </Security>}
                      RelateComponent={<CreateRelationshipButtonComponent
                        id={channel.id}
                        defaultStartTime={channel.created_at}
                        defaultStopTime={channel.updated_at}
                                       />}
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
                          to={`/dashboard/arsenal/channels/${channel.id}/knowledge/overview`}
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
                    <Routes>
                      <Route
                        path="/"
                        element={(
                          <Channel channel={props.channel} />
                        )}
                      />
                      <Route
                        path="/knowledge"
                        element={(
                          <Navigate
                            to={`/dashboard/arsenal/channels/${channelId}/knowledge/overview`}
                          />
                        )}
                      />
                      <Route
                        path="/knowledge/*"
                        element={(
                          <ChannelKnowledge
                            channel={props.channel}
                          />
                        )}
                      />
                      <Route
                        path="/analyses/*"
                        element={
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            stixDomainObjectOrStixCoreRelationship={
                              props.channel
                            }
                          />
                        }
                      />
                      <Route
                        path="/files"
                        element={ (
                          <FileManager
                            id={channelId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.channel}
                          />
                        )}
                      />
                      <Route
                        path="/history"
                        element={ (
                          <StixCoreObjectHistory
                            stixCoreObjectId={channelId}
                          />
                        )}
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

RootChannel.propTypes = {
  children: PropTypes.node,
  params: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootChannel);
