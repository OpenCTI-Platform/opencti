import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import CityOverview from './CityOverview';
import CityEdition from './CityEdition';
import CityPopover from './CityPopover';
import EntityLastReports from '../../reports/EntityLastReports';
import EntityCampaignsChart from '../../threats/campaigns/EntityCampaignsChart';
import EntityReportsChart from '../../reports/EntityReportsChart';
import EntityIncidentsChart from '../../threats/incidents/EntityIncidentsChart';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixObjectNotes from '../../common/stix_object/StixObjectNotes';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class CityComponent extends Component {
  render() {
    const { classes, city } = this.props;
    return (
      <div className={classes.container}>
        <StixDomainEntityHeader
          stixDomainEntity={city}
          PopoverComponent={<CityPopover />}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6}>
            <CityOverview city={city} />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={city.id} />
          </Grid>
        </Grid>
        <StixObjectNotes entityId={city.id} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 30 }}
        >
          <Grid item={true} xs={4}>
            <EntityCampaignsChart entityId={city.id} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityIncidentsChart entityId={city.id} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart entityId={city.id} />
          </Grid>
        </Grid>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <CityEdition cityId={city.id} />
        </Security>
      </div>
    );
  }
}

CityComponent.propTypes = {
  city: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const City = createFragmentContainer(CityComponent, {
  city: graphql`
    fragment City_city on City {
      id
      name
      alias
      ...CityOverview_city
    }
  `,
});

export default compose(inject18n, withStyles(styles))(City);
