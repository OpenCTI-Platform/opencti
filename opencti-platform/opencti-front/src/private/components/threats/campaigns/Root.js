import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Campaign from './Campaign';
import CampaignKnowledge from './CampaignKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import CampaignPopover from './CampaignPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixDomainObjectIndicators from '../../observations/indicators/StixDomainObjectIndicators';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';

const subscription = graphql`
  subscription RootCampaignSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Campaign {
        ...Campaign_campaign
        ...CampaignEditionContainer_campaign
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
  }
`;

const campaignQuery = graphql`
  query RootCampaignQuery($id: String!) {
    campaign(id: $id) {
      id
      standard_id
      name
      aliases
      ...Campaign_campaign
      ...CampaignKnowledge_campaign
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

class RootCampaign extends Component {
  componentDidMount() {
    const {
      match: {
        params: { campaignId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: campaignId },
    });
    this.setState({ sub });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { campaignId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={campaignQuery}
          variables={{ id: campaignId }}
          render={({ props }) => {
            if (props && props.campaign) {
              return (
                <div>
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
                    path="/dashboard/threats/campaigns/:campaignId/analysis"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainObjectHeader
                          stixDomainObject={props.campaign}
                          PopoverComponent={<CampaignPopover />}
                        />
                        <StixCoreObjectOrStixCoreRelationshipContainers
                          {...routeProps}
                          stixCoreObjectOrStixCoreRelationshipId={campaignId}
                        />
                      </React.Fragment>
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/threats/campaigns/:campaignId/indicators"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainObjectHeader
                          stixDomainObject={props.campaign}
                          PopoverComponent={<CampaignPopover />}
                          variant="noaliases"
                        />
                        <StixDomainObjectIndicators
                          {...routeProps}
                          stixDomainObjectId={campaignId}
                          stixDomainObjectLink={`/dashboard/threats/campaigns/${campaignId}/indicators`}
                        />
                      </React.Fragment>
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/threats/campaigns/:campaignId/indicators/relations/:relationId"
                    render={(routeProps) => (
                      <StixCoreRelationship
                        entityId={campaignId}
                        {...routeProps}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/threats/campaigns/:campaignId/files"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainObjectHeader
                          stixDomainObject={props.campaign}
                          PopoverComponent={<CampaignPopover />}
                        />
                        <FileManager
                          {...routeProps}
                          id={campaignId}
                          connectorsImport={[]}
                          connectorsExport={props.connectorsForExport}
                          entity={props.campaign}
                        />
                      </React.Fragment>
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/threats/campaigns/:campaignId/history"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainObjectHeader
                          stixDomainObject={props.campaign}
                          PopoverComponent={<CampaignPopover />}
                        />
                        <StixCoreObjectHistory
                          {...routeProps}
                          entityId={campaignId}
                        />
                      </React.Fragment>
                    )}
                  />
                </div>
              );
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
  me: PropTypes.object,
};

export default withRouter(RootCampaign);
