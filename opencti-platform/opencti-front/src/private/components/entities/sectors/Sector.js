import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import SectorOverview from './SectorOverview';
import SectorSubSectors from './SectorSubSectors';
import SectorParentSectors from './SectorParentSectors';
import SectorEdition from './SectorEdition';
import SectorPopover from './SectorPopover';
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

class SectorComponent extends Component {
  render() {
    const { classes, sector } = this.props;
    return (
      <div className={classes.container}>
        <StixDomainEntityHeader
          stixDomainEntity={sector}
          PopoverComponent={<SectorPopover />}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={3}>
            <SectorOverview sector={sector} />
          </Grid>
          <Grid item={true} xs={3}>
            {sector.isSubSector ? (
              <SectorParentSectors sector={sector} />
            ) : (
              <SectorSubSectors sector={sector} />
            )}
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={sector.id} />
          </Grid>
        </Grid>
        <StixObjectNotes entityId={sector.id} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 15 }}
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
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <SectorEdition sectorId={sector.id} />
        </Security>
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
      isSubSector
      subSectors {
        edges {
          node {
            id
          }
        }
      }
      name
      alias
      ...SectorOverview_sector
      ...SectorSubSectors_sector
      ...SectorParentSectors_sector
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Sector);
