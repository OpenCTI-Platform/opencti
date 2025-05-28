import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { Grid2 as Grid, Typography, Box } from '@mui/material';
import { PirOverviewDetailsFragment$key } from './__generated__/PirOverviewDetailsFragment.graphql';
import ExpandableMarkdown from '../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../components/i18n';
import ItemCreators from '../../../components/ItemCreators';
import FilterIconButton from '../../../components/FilterIconButton';

const detailsFragment = graphql`
  fragment PirOverviewDetailsFragment on Pir {
    description
    created_at
    creators {
      name
    }
    pir_filters
    pir_criteria {
      filters
    }
  }
`;

interface PirOverviewDetailsProps {
  data: PirOverviewDetailsFragment$key
}

const PirOverviewDetails = ({ data }: PirOverviewDetailsProps) => {
  const { t_i18n, fldt } = useFormatter();
  const pir = useFragment(detailsFragment, data);

  return (
    <Grid container spacing={2}>
      <Grid
        size={{ xs: 6 }}
        sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}
      >
        <div>
          <Typography variant="h3" gutterBottom>
            {t_i18n('Description')}
          </Typography>
          <ExpandableMarkdown source={pir.description} limit={400}/>
        </div>

        <div>
          <Typography variant="h3" gutterBottom>
            {t_i18n('Creation date')}
          </Typography>
          {fldt(pir.created_at)}
        </div>

        <div>
          <Typography variant="h3" gutterBottom>
            {t_i18n('Creators')}
          </Typography>
          <ItemCreators creators={pir.creators ?? []}/>
        </div>
      </Grid>
      <Grid
        size={{ xs: 6 }}
        sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}
      >
        <div>
          <Typography variant="h3" gutterBottom>
            {t_i18n('Filters')}
          </Typography>
          <FilterIconButton
            key={pir.pir_filters}
            filters={JSON.parse(pir.pir_filters)}
            entityTypes={['Stix-Core-Object']}
            styleNumber={1}
          />
        </div>

        <div>
          <Typography variant="h3" gutterBottom>
            {t_i18n('Criteria')}
          </Typography>
          <Box sx={{ display: 'flex', gap: 1 }}>
            {pir.pir_criteria.map((c) => (
              <FilterIconButton
                key={c.filters}
                filters={JSON.parse(c.filters)}
                entityTypes={['Stix-Core-Object']}
                styleNumber={1}
              />
            ))}
          </Box>
        </div>
      </Grid>
    </Grid>
  );
};

export default PirOverviewDetails;
