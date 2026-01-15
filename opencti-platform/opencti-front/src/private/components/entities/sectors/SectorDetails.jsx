import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import SectorParentSectors from './SectorParentSectors';
import SectorSubSectors from './SectorSubSectors';
import Label from '../../../../components/common/label/Label';

class SectorDetailsComponent extends Component {
  render() {
    const { t, sector } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Card title={t('Details')}>
          <Grid container={true} spacing={3}>
            <Grid item xs={6}>
              <Label>
                {t('Description')}
              </Label>
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
        </Card>
      </div>
    );
  }
}

SectorDetailsComponent.propTypes = {
  sector: PropTypes.object,
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

export default compose(inject18n)(SectorDetails);
