import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch, Link } from 'react-router-dom';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import * as R from 'ramda';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import Campaign from './Campaign';
import CampaignKnowledge from './CampaignKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import CampaignPopover from './CampaignPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import inject18n from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';

const subscription = graphql`
  subscription RootCampaignSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Campaign {
        ...Campaign_campaign
        ...CampaignEditionContainer_campaign
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const campaignQuery = graphql`
  query RootCampaignQuery($id: String!) {
    campaign(id: $id) {
      id
      standard_id
      entity_type
      name
      aliases
      x_opencti_graph_data
      ...Campaign_campaign
      ...CampaignKnowledge_campaign
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

class RootCampaign extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { campaignId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: campaignId },
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
        params: { campaignId },
      },
    } = this.props;
    const link = `/dashboard/threats/campaigns/${campaignId}/knowledge`;
    return (
      <div>
        <Route path="/dashboard/threats/campaigns/:campaignId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'attribution',
              'victimology',
              'incidents',
              'malwares',
              'tools',
              'channels',
              'narratives',
              'attack_patterns',
              'vulnerabilities',
              'indicators',
              'observables',
              'infrastructures',
              'sightings',
            ]}
          />
        </Route>
        <QueryRenderer
          query={campaignQuery}
          variables={{ id: campaignId }}
          render={({ props }) => {
            if (props) {
              if (props.campaign) {
                const { campaign } = props;
                return (
                  <div
                    style={{
                      paddingRight: location.pathname.includes(
                        `/dashboard/threats/campaigns/${campaign.id}/knowledge`,
                      )
                        ? 200
                        : 0,
                    }}
                  >
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Threats') },
                      { label: t('Campaigns'), link: '/dashboard/threats/campaigns' },
                      { label: campaign.name, current: true },
                    ]}
                    />
                    <StixDomainObjectHeader
                      entityType="Campaign"
                      stixDomainObject={campaign}
                      PopoverComponent={<CampaignPopover />}
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
                            `/dashboard/threats/campaigns/${campaign.id}/knowledge`,
                          )
                            ? `/dashboard/threats/campaigns/${campaign.id}/knowledge`
                            : location.pathname
                        }
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/threats/campaigns/${campaign.id}`}
                          value={`/dashboard/threats/campaigns/${campaign.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/threats/campaigns/${campaign.id}/knowledge`}
                          value={`/dashboard/threats/campaigns/${campaign.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/threats/campaigns/${campaign.id}/analyses`}
                          value={`/dashboard/threats/campaigns/${campaign.id}/analyses`}
                          label={t('Analyses')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/threats/campaigns/${campaign.id}/files`}
                          value={`/dashboard/threats/campaigns/${campaign.id}/files`}
                          label={t('Data')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/threats/campaigns/${campaign.id}/history`}
                          value={`/dashboard/threats/campaigns/${campaign.id}/history`}
                          label={t('History')}
                        />
                      </Tabs>
                    </Box>
                    <Switch>
                      <Route
                        exact
                        path="/dashboard/threats/campaigns/:campaignId"
                        render={(routeProps) => (
                          <Campaign {...routeProps} campaign={props.campaign} />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/threats/campaigns/:campaignId/knowledge"
                        render={() => (
                          <Redirect
                            to={`/dashboard/threats/campaigns/${campaignId}/knowledge/overview`}
                          />
                        )}
                      />
                      <Route
                        path="/dashboard/threats/campaigns/:campaignId/knowledge"
                        render={(routeProps) => (
                          <CampaignKnowledge
                            {...routeProps}
                            campaign={props.campaign}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/threats/campaigns/:campaignId/analyses"
                        render={(routeProps) => (
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.campaign
                            }
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/threats/campaigns/:campaignId/files"
                        render={(routeProps) => (
                          <FileManager
                            {...routeProps}
                            id={campaignId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.campaign}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/threats/campaigns/:campaignId/history"
                        render={(routeProps) => (
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={campaignId}
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

RootCampaign.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootCampaign);
