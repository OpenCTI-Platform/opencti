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
import CampaignReports from './CampaignReports';
import CampaignKnowledge from './CampaignKnowledge';
import CampaignObservables from './CampaignObservables';

const subscription = graphql`
  subscription RootCampaignSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ... on Campaign {
        ...Campaign_campaign
        ...CampaignEditionContainer_campaign
      }
    }
  }
`;

const campaignQuery = graphql`
  query RootCampaignQuery($id: String!) {
    campaign(id: $id) {
      ...Campaign_campaign
      ...CampaignHeader_campaign
      ...CampaignOverview_campaign
      ...CampaignDetails_campaign
      ...CampaignReports_campaign
      ...CampaignKnowledge_campaign
      ...CampaignObservables_campaign
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
                    render={routeProps => (
                      <Campaign {...routeProps} campaign={props.campaign} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/threats/campaigns/:campaignId/reports"
                    render={routeProps => (
                      <CampaignReports
                        {...routeProps}
                        campaign={props.campaign}
                      />
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
                    render={routeProps => (
                      <CampaignKnowledge
                        {...routeProps}
                        campaign={props.campaign}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/threats/campaigns/:campaignId/observables"
                    render={routeProps => (
                      <CampaignObservables
                        {...routeProps}
                        campaign={props.campaign}
                      />
                    )}
                  />
                </div>
              );
            }
            return <div> &nbsp; </div>;
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
