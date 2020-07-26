import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import CountryOverview from './CountryOverview';
import CountryEdition from './CountryEdition';
import CountryPopover from './CountryPopover';
import EntityLastReports from '../../reports/EntityLastReports';
import EntityCampaignsChart from '../../threats/campaigns/EntityCampaignsChart';
import EntityReportsChart from '../../reports/EntityReportsChart';
import EntityXOpenctiIncidentsChart from '../../threats/x_opencti_incidents/EntityXOpenctiIncidentsChart';
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

class CountryComponent extends Component {
  render() {
    const { classes, country } = this.props;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={country}
          PopoverComponent={<CountryPopover />}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6}>
            <CountryOverview country={country} />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={country.id} />
          </Grid>
        </Grid>
        <StixCoreObjectNotes entityId={country.id} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 15 }}
        >
          <Grid item={true} xs={4}>
            <EntityCampaignsChart entityId={country.id} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityXOpenctiIncidentsChart entityId={country.id} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart entityId={country.id} />
          </Grid>
        </Grid>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <CountryEdition countryId={country.id} />
        </Security>
      </div>
    );
  }
}

CountryComponent.propTypes = {
  country: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Country = createFragmentContainer(CountryComponent, {
  country: graphql`
    fragment Country_country on Country {
      id
      name
      x_opencti_aliases
      ...CountryOverview_country
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Country);
