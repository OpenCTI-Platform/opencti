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
import CampaignEdition from './CampaignEdition';
import EntityLastReports from '../report/EntityLastReports';
import EntityObservablesChart from '../observable/EntityObservablesChart';
import EntityReportsChart from '../report/EntityReportsChart';
import EntityKillChainPhasesChart from '../kill_chain_phase/EntityKillChainPhasesChart';
import { requestSubscription } from '../../../relay/environment';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

const subscription = graphql`
    subscription CampaignSubscription($id: ID!) {
        stixDomainEntity(id: $id) {
            ...on Campaign {
                ...Campaign_campaign   
            }
        }
    }
`;

class CampaignComponent extends Component {
  componentDidMount() {
    const sub = requestSubscription({
      subscription,
      variables: {
        id: this.props.campaign.id,
      },
    });
    this.setState({
      sub,
    });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
  }

  render() {
    const { classes, campaign } = this.props;
    return (
      <div className={classes.container}>
        <CampaignHeader campaign={campaign}/>
        <Grid container={true} spacing={32} classes={{ container: classes.gridContainer }}>
          <Grid item={true} xs={6}>
            <CampaignOverview campaign={campaign}/>
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={campaign.id}/>
          </Grid>
        </Grid>
        <Grid container={true} spacing={32} classes={{ container: classes.gridContainer }} style={{ marginTop: 20 }}>
          <Grid item={true} xs={4}>
            <EntityObservablesChart campaign={campaign}/>
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart campaign={campaign}/>
          </Grid>
          <Grid item={true} xs={4}>
            <EntityKillChainPhasesChart campaign={campaign}/>
          </Grid>
        </Grid>
        <CampaignEdition campaignId={campaign.id}/>
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
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(Campaign);
