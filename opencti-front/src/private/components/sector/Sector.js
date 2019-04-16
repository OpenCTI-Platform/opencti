import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../components/i18n';
import SectorHeader from './SectorHeader';
import SectorOverview from './SectorOverview';
import SectorSubsectors from './SectorSubsectors';
import SectorEdition from './SectorEdition';
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

class SectorComponent extends Component {
  render() {
    const { classes, sector } = this.props;
    return (
      <div className={classes.container}>
        <SectorHeader sector={sector} />
        <Grid
          container={true}
          spacing={32}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={sector.subsectors.edges.length > 0 ? 3 : 6}>
            <SectorOverview sector={sector} />
          </Grid>
          {sector.subsectors.edges.length > 0 ? (
            <Grid item={true} xs={3}>
              <SectorSubsectors sector={sector} />
            </Grid>
          ) : (
            ''
          )}
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={sector.id} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={32}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 20 }}
        >
          <Grid item={true} xs={4}>
            <EntityCampaignsChart entityId={sector.id} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityIncidentsChart entityId={sector.id} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart entityId={sector.id} />
          </Grid>
        </Grid>
        <SectorEdition sectorId={sector.id} />
      </div>
    );
  }
}

SectorComponent.propTypes = {
  sector: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Sector = createFragmentContainer(SectorComponent, {
  sector: graphql`
    fragment Sector_sector on Sector {
      id
      subsectors {
        edges {
          node {
            id
          }
        }
      }
      ...SectorHeader_sector
      ...SectorOverview_sector
      ...SectorSubsectors_sector
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(Sector);
