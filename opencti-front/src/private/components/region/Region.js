import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../components/i18n';
import RegionHeader from './RegionHeader';
import RegionOverview from './RegionOverview';
import RegionEdition from './RegionEdition';
import EntityLastReports from '../report/EntityLastReports';
import EntityCampaignsChart from '../campaign/EntityCampaignsChart';
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

class RegionComponent extends Component {
  render() {
    const { classes, region } = this.props;
    return (
      <div className={classes.container}>
        <RegionHeader region={region} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6}>
            <RegionOverview region={region} />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={region.id} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 30 }}
        >
          <Grid item={true} xs={4}>
            <EntityCampaignsChart entityId={region.id} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityIncidentsChart entityId={region.id} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart entityId={region.id} />
          </Grid>
        </Grid>
        <RegionEdition regionId={region.id} />
      </div>
    );
  }
}

RegionComponent.propTypes = {
  region: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Region = createFragmentContainer(RegionComponent, {
  region: graphql`
    fragment Region_region on Region {
      id
      ...RegionHeader_region
      ...RegionOverview_region
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(Region);
