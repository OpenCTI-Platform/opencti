import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import SectorParentSectors from './SectorParentSectors';
import SectorSubSectors from './SectorSubSectors';

const styles = (theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
});

class SectorDetailsComponent extends Component {
  render() {
    const { t, classes, sector } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
          <Grid container={true} spacing={3}>
            <Grid item xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Description')}
              </Typography>
              <ExpandableMarkdown source={sector.description} limit={400} />
            </Grid>
            <Grid item xs={6}>
              {sector.isSubSector ? (
                <SectorParentSectors sector={sector} />
              ) : (
                <SectorSubSectors sector={sector} />
              )}
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

SectorDetailsComponent.propTypes = {
  sector: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const SectorDetails = createFragmentContainer(SectorDetailsComponent, {
  sector: graphql`
    fragment SectorDetails_sector on Sector {
      id
      description
      isSubSector
      ...SectorSubSectors_sector
      ...SectorParentSectors_sector
    }
  `,
});

export default compose(inject18n, withStyles(styles))(SectorDetails);
