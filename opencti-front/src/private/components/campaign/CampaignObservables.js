import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Route, withRouter } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../components/i18n';
import CampaignHeader from './CampaignHeader';
import StixRelation from '../stix_relation/StixRelation';
import EntityStixObservables from '../stix_observable/EntityStixObservables';

const styles = theme => ({
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
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
});

const inversedRelations = [];

class CampaignObservablesComponent extends Component {
  render() {
    const { classes, campaign, location } = this.props;
    const link = `/dashboard/knowledge/campaigns/${
      campaign.id
    }/observables`;
    return (
      <div
        className={
          location.pathname.includes(
            `/dashboard/knowledge/campaigns/${
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
          path="/dashboard/knowledge/campaigns/:campaignId/observables/relations/:relationId"
          render={routeProps => (
            <StixRelation
              entityId={campaign.id}
              inversedRelations={inversedRelations}
              observable={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/knowledge/campaigns/:campaignId/observables"
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
