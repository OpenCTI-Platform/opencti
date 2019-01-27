import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer } from '../../../relay/environment';
import TopBar from '../nav/TopBar';
import Campaign from './Campaign';
import CampaignReports from './CampaignReports';
import CampaignKnowledge from './CampaignKnowledge';

const campaignQuery = graphql`
    query RootCampaignQuery($id: String!) {
        campaign(id: $id) {
            ...Campaign_campaign
            ...CampaignHeader_campaign
            ...CampaignOverview_campaign
            ...CampaignReports_campaign
            ...CampaignKnowledge_campaign
        }
    }
`;

class RootCampaign extends Component {
  render() {
    const { me, match: { params: { campaignId } } } = this.props;
    return (
      <div>
        <TopBar me={me || null}/>
        <QueryRenderer
          query={campaignQuery}
          variables={{ id: campaignId }}
          render={({ props }) => {
            if (props && props.campaign) {
              return (
                <div>
                  <Route exact path='/dashboard/knowledge/campaigns/:campaignId' render={
                    routeProps => <Campaign {...routeProps} campaign={props.campaign}/>
                  }/>
                  <Route exact path='/dashboard/knowledge/campaigns/:campaignId/reports' render={
                    routeProps => <CampaignReports {...routeProps} campaign={props.campaign}/>
                  }/>
                  <Route exact path='/dashboard/knowledge/campaigns/:campaignId/knowledge' render={
                    () => (<Redirect to={`/dashboard/knowledge/campaigns/${campaignId}/knowledge/overview`}/>)
                  }/>
                  <Route path='/dashboard/knowledge/campaigns/:campaignId/knowledge' render={
                    routeProps => <CampaignKnowledge {...routeProps} campaign={props.campaign}/>
                  }/>
                </div>
              );
            }
            return (
              <div> &nbsp; </div>
            );
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
