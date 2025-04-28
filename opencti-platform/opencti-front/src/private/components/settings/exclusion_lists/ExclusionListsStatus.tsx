import { graphql, PreloadedQuery, usePreloadedQuery, UseQueryLoaderLoadQueryOptions } from 'react-relay';
import { ExclusionListsStatusQuery, ExclusionListsStatusQuery$variables } from '@components/settings/exclusion_lists/__generated__/ExclusionListsStatusQuery.graphql';
import Paper from '@mui/material/Paper';
import { useTheme } from '@mui/styles';
import React, { FunctionComponent, useEffect } from 'react';
import { EventRepeatOutlined, UpdateOutlined } from '@mui/icons-material';
import Grid from '@mui/material/Grid';
import type { Theme } from 'src/components/Theme';
import { interval } from 'rxjs';
import CircularProgress from '@mui/material/CircularProgress';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { TEN_SECONDS } from '../../../../utils/Time';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import ItemBoolean from '../../../../components/ItemBoolean';

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

  setTitle(t_i18n('Exclusion lists | Customization | Settings'));

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
    <Grid container spacing={2}>
      <Grid item xs={4}>
        <Typography variant={'h4'}>
          {t_i18n('Status')}
        </Typography>
        <Paper
          variant="outlined"
          style={{
            display: 'flex',
            padding: theme.spacing(2),
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
          className={'paper-for-grid'}
        >
          <ItemBoolean
            neutralLabel={'In progress'}
            label={'Synchronized'}
            status={(isInProgress === false) || null}
          />
          {isInProgress && (
            <CircularProgress
              size={40}
              thickness={2}
              color="primary"
            />
          )}
        </Paper>
      </Grid>
      <Grid item xs={4}>
        <Typography variant={'h4'}>
          {t_i18n('Last modification date')}
        </Typography>
        <Paper
          variant="outlined"
          style={{
            display: 'flex',
            padding: theme.spacing(2),
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
          className={'paper-for-grid'}
        >
          <div>{fldt(refreshDate)}</div>
          <UpdateOutlined color="primary" style={{ fontSize: 40 }} />
        </Paper>
      </Grid>
      <Grid item xs={4}>
        <Typography variant={'h4'}>
          {t_i18n('Current cache version date')}
        </Typography>
        <Paper
          variant="outlined"
          style={{
            display: 'flex',
            padding: theme.spacing(2),
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
          className={'paper-for-grid'}
        >
          <div>{fldt(cacheDate)}</div>
          <EventRepeatOutlined color="primary" style={{ fontSize: 40 }} />
        </Paper>
      </Grid>
    </Grid>
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
