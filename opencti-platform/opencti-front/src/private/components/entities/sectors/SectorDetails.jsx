import React from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import SectorParentSectors from './SectorParentSectors';
import SectorSubSectors from './SectorSubSectors';
import Label from '../../../../components/common/label/Label';

const SectorDetailsComponent = (props) => {
  const { t_i18n } = useFormatter();
  const { sector } = props;
  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={12}>
            <Label>
              {t_i18n('Description')}
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
};

SectorDetailsComponent.propTypes = {
  sector: PropTypes.object,
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

export default SectorDetails;
