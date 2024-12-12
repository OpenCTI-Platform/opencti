import { graphql } from 'react-relay';
import { ExclusionListsStatusQuery$data } from '@components/settings/exclusion_lists/__generated__/ExclusionListsStatusQuery.graphql';
import Paper from '@mui/material/Paper';
import { useTheme } from '@mui/styles';
import Chip from '@mui/material/Chip';
import React from 'react';
import { EventRepeatOutlined, SyncDisabledOutlined, SyncOutlined, UpdateOutlined } from '@mui/icons-material';
import Grid from '@mui/material/Grid';
import { Theme } from 'src/components/Theme';
import { useFormatter } from '../../../../components/i18n';

export const exclusionListsStatusQuery = graphql`
  query ExclusionListsStatusQuery {
    exclusionListCacheStatus{
      refreshVersion
      cacheVersion
      isCacheRebuildInProgress
    }
  }
`;

const ExclusionListsStatus = ({ data }: { data: ExclusionListsStatusQuery$data }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();
  const isInProgress = data.exclusionListCacheStatus?.isCacheRebuildInProgress;
  return (
    <>
      <Grid container={true} spacing={3} style={{ marginBottom: theme.spacing(1) }}>
        <Grid item xs={4}>
          <Paper
            variant="outlined"
            style={{ display: 'flex', padding: 20, height: 100, position: 'relative' }}
            className={'paper-for-grid'}
          >
            <div style={{ position: 'absolute', top: 25, right: 15 }}>
              {isInProgress ? (
                <SyncOutlined color="primary" sx={{ fontSize: 40 }} />
              ) : (
                <SyncDisabledOutlined color="primary" sx={{ fontSize: 40 }} />
              )}
            </div>
            <div>
              <div style={{ textTransform: 'uppercase', fontSize: 12, fontWeight: 500, color: theme.palette.text?.secondary }}>
                {t_i18n('Status')}
              </div>
              {isInProgress ? (
                <Chip
                  style={{
                    backgroundColor: 'rgba(76, 175, 80, 0.08)',
                    color: '#4caf50',
                    fontSize: 20,
                    fontWeight: 800,
                    textTransform: 'uppercase',
                    borderRadius: 4,
                  }}
                  label={t_i18n('In progress')}
                />
              ) : (
                <Chip
                  style={{
                    backgroundColor: 'rgba(92, 123, 245, 0.08)',
                    color: '#5c7bf5',
                    fontSize: 20,
                    fontWeight: 800,
                    textTransform: 'uppercase',
                    borderRadius: 4,
                  }}
                  label={t_i18n('Synchronized')}
                />
              )}
            </div>
          </Paper>
        </Grid>
        <Grid item xs={4}>
          <Paper
            variant="outlined"
            style={{ display: 'flex', padding: 20, height: 100, position: 'relative' }}
            className={'paper-for-grid'}
          >
            <div style={{ position: 'absolute', top: 25, right: 15 }}>
              <EventRepeatOutlined color="primary" sx={{ fontSize: 40 }} />
            </div>
            <div>
              <div style={{ textTransform: 'uppercase', fontSize: 12, fontWeight: 500, color: theme.palette.text?.secondary }}>
                {t_i18n('Cache date')}
              </div>
              <div>
                {fldt(data.exclusionListCacheStatus?.cacheVersion)}
              </div>
            </div>
          </Paper>
        </Grid>
        <Grid item xs={4}>
          <Paper
            variant="outlined"
            style={{ display: 'flex', padding: 20, height: 100, position: 'relative' }}
            className={'paper-for-grid'}
          >
            <div style={{ position: 'absolute', top: 25, right: 15 }}>
              <UpdateOutlined color="primary" sx={{ fontSize: 40 }} />
            </div>
            <div>
              <div style={{ textTransform: 'uppercase', fontSize: 12, fontWeight: 500, color: theme.palette.text?.secondary }}>
                {t_i18n('Refresh date')}
              </div>
              <div>
                {fldt(data.exclusionListCacheStatus?.refreshVersion)}
              </div>
            </div>
          </Paper>
        </Grid>
      </Grid>
    </>
  );
};

export default ExclusionListsStatus;
