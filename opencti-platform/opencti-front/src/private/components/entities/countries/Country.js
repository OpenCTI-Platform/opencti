import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import CountryHeader from './CountryHeader';
import CountryOverview from './CountryOverview';
import CountryEdition from './CountryEdition';
import EntityLastReports from '../../reports/EntityLastReports';
import EntityCampaignsChart from '../../threats/campaigns/EntityCampaignsChart';
import EntityReportsChart from '../../reports/EntityReportsChart';
import EntityIncidentsChart from '../../threats/incidents/EntityIncidentsChart';

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
        <CountryHeader country={country} />
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
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 30 }}
        >
          <Grid item={true} xs={4}>
            <EntityCampaignsChart entityId={country.id} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityIncidentsChart entityId={country.id} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart entityId={country.id} />
          </Grid>
        </Grid>
        <CountryEdition countryId={country.id} />
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
      ...CountryHeader_country
      ...CountryOverview_country
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(Country);
