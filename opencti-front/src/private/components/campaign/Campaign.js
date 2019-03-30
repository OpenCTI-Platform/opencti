import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../components/i18n';
import CampaignHeader from './CampaignHeader';
import CampaignOverview from './CampaignOverview';
import CampaignIdentity from './CampaignIdentity';
import CampaignEdition from './CampaignEdition';
import EntityLastReports from '../report/EntityLastReports';
import EntityObservablesChart from '../observable/EntityObservablesChart';
import EntityReportsChart from '../report/EntityReportsChart';
import EntityIncidentsChart from '../incident/EntityIncidentsChart';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class CampaignComponent extends Component {
  render() {
    const { classes, campaign } = this.props;
    return (
      <div className={classes.container}>
        <CampaignHeader campaign={campaign} />
        <Grid
          container={true}
          spacing={32}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={3}>
            <CampaignOverview campaign={campaign} />
          </Grid>
          <Grid item={true} xs={3}>
            <CampaignIdentity campaign={campaign} />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={campaign.id} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={32}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 20 }}
        >
          <Grid item={true} xs={4}>
            <EntityIncidentsChart entityId={campaign.id} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityObservablesChart entityId={campaign.id} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart entityId={campaign.id} />
          </Grid>
        </Grid>
        <CampaignEdition campaignId={campaign.id} />
      </div>
    );
  }
}

CampaignComponent.propTypes = {
  campaign: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Campaign = createFragmentContainer(CampaignComponent, {
  campaign: graphql`
    fragment Campaign_campaign on Campaign {
      id
      ...CampaignHeader_campaign
      ...CampaignOverview_campaign
      ...CampaignIdentity_campaign
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(Campaign);
