import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import CampaignOverview from './CampaignOverview';
import CampaignDetails from './CampaignDetails';
import CampaignEdition from './CampaignEdition';
import CampaignPopover from './CampaignPopover';
import EntityLastReports from '../../reports/EntityLastReports';
import EntityStixCoreRelationshipsDonut from '../../common/stix_core_relationships/EntityStixCoreRelationshipsDonut';
import EntityReportsChart from '../../reports/EntityReportsChart';
import EntityXOpenCTIIncidentsChart from '../x_opencti_incidents/EntityXOpenCTIIncidentsChart';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreObjectNotes from '../../common/stix_core_objects/StixCoreObjectNotes';

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
        <StixDomainObjectHeader
          stixDomainObject={campaign}
          PopoverComponent={<CampaignPopover />}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={3}>
            <CampaignOverview campaign={campaign} />
          </Grid>
          <Grid item={true} xs={3}>
            <CampaignDetails campaign={campaign} />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={campaign.id} />
          </Grid>
        </Grid>
        <StixCoreObjectNotes entityId={campaign.id} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 15 }}
        >
          <Grid item={true} xs={4}>
            <EntityXOpenCTIIncidentsChart
              entityId={campaign.id}
              relationshipType="attributed-to"
            />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityStixCoreRelationshipsDonut
              entityId={campaign.id}
              entityType="Indicator"
              relationshipType="indicates"
              field="x_opencti_main_observable_type"
            />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart entityId={campaign.id} />
          </Grid>
        </Grid>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <CampaignEdition campaignId={campaign.id} />
        </Security>
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
      name
      aliases
      ...CampaignOverview_campaign
      ...CampaignDetails_campaign
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Campaign);
