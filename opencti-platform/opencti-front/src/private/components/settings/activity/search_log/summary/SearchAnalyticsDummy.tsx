import React from 'react';
import Grid from '@mui/material/Grid2';
import SummaryCard from './SummaryCard';
import { useFormatter } from '../../../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../../../components/Loader';
import type { Theme } from '../../../../../../components/Theme';
import makeStyles from '@mui/styles/makeStyles';

const useStyles = makeStyles<Theme>(() => ({
  countCard: {
    flex: 1,
    display: 'flex',
    alignItems: 'center',
    fontSize: '24px',
  },
}));

const SearchAnalyticsDummy = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  return (
    <Grid container spacing={2}>
      <Grid container size={12} spacing={2}>

        <SummaryCard title={t_i18n('Searches')} size={3} height={100}>
          <div className={classes.countCard}>
            <Loader variant={LoaderVariant.inline} />
          </div>
        </SummaryCard>

        <SummaryCard title={t_i18n('Locations')} size={3} height={100}>
          <div className={classes.countCard}>
            <Loader variant={LoaderVariant.inline} />
          </div>
        </SummaryCard>

        <SummaryCard title={t_i18n('Organizations')} size={3} height={100}>
          <div className={classes.countCard}>
            <Loader variant={LoaderVariant.inline} />
          </div>
        </SummaryCard>

        <SummaryCard title={t_i18n('Users')} size={3} height={100}>
          <div className={classes.countCard}>
            <Loader variant={LoaderVariant.inline} />
          </div>
        </SummaryCard>
      </Grid>
      <Grid container size={12}>
        <SummaryCard title={t_i18n('Search result count distribution')} size={4} height={200} padding={0}>
          <Loader variant={LoaderVariant.inElement} />
        </SummaryCard>
        <SummaryCard title={t_i18n('Locations')} size={4} height={200}>
          <Loader variant={LoaderVariant.inElement} />
        </SummaryCard>
        <SummaryCard title={t_i18n('Organizations')} size={4} height={200}>
          <Loader variant={LoaderVariant.inElement} />
        </SummaryCard>
      </Grid>
      <Grid container size={12}>
        <SummaryCard title={t_i18n('Top 10 searches with no results (#)')} size={6} height={325}>
          <Loader variant={LoaderVariant.inElement} />
        </SummaryCard>
        <SummaryCard title={t_i18n('Top 10 searches with results (#)')} size={6} height={325}>
          <Loader variant={LoaderVariant.inElement} />
        </SummaryCard>
      </Grid>
    </Grid>
  );
};

export default SearchAnalyticsDummy;
