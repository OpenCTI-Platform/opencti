import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Route, withRouter } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import CampaignHeader from './CampaignHeader';
import StixRelation from '../../common/stix_relations/StixRelation';
import EntityStixObservables from '../../stix_observables/EntityStixObservables';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
  },
  containerWithoutPadding: {
    margin: 0,
    padding: 0,
  },
  paper: {
    minHeight: '100%',
    margin: '5px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class CampaignObservablesComponent extends Component {
  render() {
    const { classes, campaign, location } = this.props;
    const link = `/dashboard/threats/campaigns/${campaign.id}/observables`;
    return (
      <div
        className={
          location.pathname.includes(
            `/dashboard/threats/campaigns/${
              campaign.id
            }/observables/relations/`,
          )
            ? classes.containerWithoutPadding
            : classes.container
        }
      >
        <CampaignHeader campaign={campaign} variant="noalias" />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/observables/relations/:relationId"
          render={routeProps => (
            <StixRelation
              entityId={campaign.id}
              inversedRoles={[]}
              observable={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/observables"
          render={routeProps => (
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <EntityStixObservables
                entityId={campaign.id}
                relationType="indicates"
                entityLink={link}
                {...routeProps}
              />
            </Paper>
          )}
        />
      </div>
    );
  }
}

CampaignObservablesComponent.propTypes = {
  campaign: PropTypes.object,
  location: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const CampaignObservables = createFragmentContainer(
  CampaignObservablesComponent,
  {
    campaign: graphql`
      fragment CampaignObservables_campaign on Campaign {
        id
        ...CampaignHeader_campaign
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(CampaignObservables);
