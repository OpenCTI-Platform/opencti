import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Route, withRouter } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import CampaignPopover from './CampaignPopover';
import StixRelation from '../../common/stix_relations/StixRelation';
import EntityIndicators from '../../signatures/indicators/EntityIndicators';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';

const styles = () => ({
  container: {
    margin: 0,
  },
  containerWithoutPadding: {
    margin: 0,
    padding: 0,
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '5px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class CampaignIndicatorsComponent extends Component {
  render() {
    const { classes, campaign, location } = this.props;
    const link = `/dashboard/threats/campaigns/${campaign.id}/indicators`;
    return (
      <div
        className={
          location.pathname.includes(
            `/dashboard/threats/campaigns/${campaign.id}/indicators/relations/`,
          )
            ? classes.containerWithoutPadding
            : classes.container
        }
      >
        <StixDomainEntityHeader
          stixDomainEntity={campaign}
          PopoverComponent={<CampaignPopover />}
        />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/indicators/relations/:relationId"
          render={(routeProps) => (
            <StixRelation
              entityId={campaign.id}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/campaigns/:campaignId/indicators"
          render={(routeProps) => (
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <EntityIndicators
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

CampaignIndicatorsComponent.propTypes = {
  campaign: PropTypes.object,
  location: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const CampaignIndicators = createFragmentContainer(
  CampaignIndicatorsComponent,
  {
    campaign: graphql`
      fragment CampaignIndicators_campaign on Campaign {
        id
        name
        alias
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(CampaignIndicators);
