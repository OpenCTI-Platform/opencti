import { graphql, PreloadedQuery, usePreloadedQuery, UseQueryLoaderLoadQueryOptions } from 'react-relay';
import { ExclusionListsStatusQuery, ExclusionListsStatusQuery$variables } from '@components/settings/exclusion_lists/__generated__/ExclusionListsStatusQuery.graphql';
import Paper from '@mui/material/Paper';
import { useTheme } from '@mui/styles';
import Chip from '@mui/material/Chip';
import React, { FunctionComponent, useEffect } from 'react';
import { EventRepeatOutlined, UpdateOutlined } from '@mui/icons-material';
import Grid from '@mui/material/Grid';
import { Theme } from 'src/components/Theme';
import { interval } from 'rxjs';
import CircularProgress from '@mui/material/CircularProgress';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { TEN_SECONDS } from '../../../../utils/Time';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';

const interval$ = interval(TEN_SECONDS);

export const exclusionListsStatusQuery = graphql`
  query ExclusionListsStatusQuery {
    exclusionListCacheStatus{
      refreshVersion
      cacheVersion
      isCacheRebuildInProgress
    }
  }
`;

interface ExclusionListsStatusComponentProps {
  queryRef: PreloadedQuery<ExclusionListsStatusQuery>;
  refetch: () => void;
}

const ExclusionListsStatusComponent: FunctionComponent<ExclusionListsStatusComponentProps> = ({ queryRef, refetch }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();
  const { exclusionListCacheStatus } = usePreloadedQuery(
    exclusionListsStatusQuery,
    queryRef,
  );
  const { setTitle } = useConnectedDocumentModifier();

  setTitle(t_i18n('Customization: Exclusion lists | Settings'));

  const isInProgress = exclusionListCacheStatus?.isCacheRebuildInProgress;
  const cacheDate = exclusionListCacheStatus?.cacheVersion;
  const refreshDate = exclusionListCacheStatus?.refreshVersion;

  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      refetch();
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, []);

  return (
    <>
      <Grid container spacing={3} style={{ marginBottom: '20px' }}>
        <Grid item xs={4}>
          <Paper
            variant="outlined"
            style={{ display: 'flex', justifyContent: 'space-between', padding: 20, height: 100 }}
            className={'paper-for-grid'}
          >
            <div>
              <div style={{ textTransform: 'uppercase', fontSize: 12, fontWeight: 500, color: theme.palette.text?.secondary }}>
                {t_i18n('Status')}
              </div>
              <Chip
                style={{
                  backgroundColor: isInProgress ? 'rgba(92, 123, 245, 0.08)' : 'rgba(76, 175, 80, 0.08)',
                  color: isInProgress ? '#5c7bf5' : '#4caf50',
                  fontSize: 20,
                  fontWeight: 800,
                  textTransform: 'uppercase',
                  borderRadius: 4,
                }}
                label={isInProgress ? t_i18n('In progress') : t_i18n('Synchronized')}
              />
            </div>
            {isInProgress && (
              <div style={{ margin: 'auto 0' }}>
                <CircularProgress
                  size={40}
                  thickness={2}
                  color="primary"
                />
              </div>
            )}
          </Paper>
        </Grid>
        <Grid item xs={4}>
          <Paper
            variant="outlined"
            style={{ display: 'flex', padding: 20, height: 100, position: 'relative' }}
            className={'paper-for-grid'}
          >
            <UpdateOutlined color="primary" style={{ fontSize: 40, position: 'absolute', top: 25, right: 15 }} />
            <div>
              <div style={{ textTransform: 'uppercase', fontSize: 12, fontWeight: 500, color: theme.palette.text?.secondary }}>
                {t_i18n('Last modification date')}
              </div>
              <div>{fldt(refreshDate)}</div>
            </div>
          </Paper>
        </Grid>
        <Grid item xs={4}>
          <Paper
            variant="outlined"
            style={{ display: 'flex', padding: 20, height: 100, position: 'relative' }}
            className={'paper-for-grid'}
          >
            <EventRepeatOutlined color="primary" style={{ fontSize: 40, position: 'absolute', top: 25, right: 15 }} />
            <div>
              <div style={{ textTransform: 'uppercase', fontSize: 12, fontWeight: 500, color: theme.palette.text?.secondary }}>
                {t_i18n('Current cache version date')}
              </div>
              <div>{fldt(cacheDate)}</div>
            </div>
          </Paper>
        </Grid>
      </Grid>
    </>
  );
};

interface ExclusionListsStatusProps {
  queryRef: PreloadedQuery<ExclusionListsStatusQuery> | null | undefined;
  refetch: () => void;
  loadQuery: (variables: ExclusionListsStatusQuery$variables, options?: UseQueryLoaderLoadQueryOptions) => void;
}

const ExclusionListsStatus: FunctionComponent<ExclusionListsStatusProps> = ({ refetch, queryRef, loadQuery }) => {
  useEffect(() => {
    loadQuery({}, { fetchPolicy: 'store-and-network' });
  }, []);

  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <ExclusionListsStatusComponent queryRef={queryRef} refetch={refetch} />
        </React.Suspense>
      )}
    </>
  );
};

export default ExclusionListsStatus;
