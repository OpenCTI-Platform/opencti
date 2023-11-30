import React, { FunctionComponent, useEffect } from 'react';
import Box from '@mui/material/Box';
import Tab from '@mui/material/Tab';
import Tabs from '@mui/material/Tabs';
import { Link, Redirect, Switch, useParams } from 'react-router-dom';
import Typography from '@mui/material/Typography';
import { BoundaryRoute } from '@components/Error';
import Search from '@components/Search';
import SearchIndexedFiles from '@components/search/SearchIndexedFiles';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import ExportContextProvider from '../../utils/ExportContextProvider';
import { useFormatter } from '../../components/i18n';
import { decodeSearchKeyword } from '../../utils/SearchUtils';
import useAuth from '../../utils/hooks/useAuth';
import { SearchRootFilesCountQuery } from './__generated__/SearchRootFilesCountQuery.graphql';

const searchRootFilesCountQuery = graphql`
  query SearchRootFilesCountQuery($search: String) {
    indexedFilesCount(search: $search)
  }
`;

interface SearchRootComponentProps {
  queryRef: PreloadedQuery<SearchRootFilesCountQuery> | null | undefined;
}

const SearchRootComponent: FunctionComponent<SearchRootComponentProps> = ({ queryRef }) => {
  const { t } = useFormatter();
  const { scope } = useParams() as { scope: string };
  const { keyword } = useParams() as { keyword: string };
  const searchType = ['knowledge', 'files'].includes(scope) ? scope : 'knowledge';
  let filesCount = 0;
  if (queryRef) {
    const { indexedFilesCount } = usePreloadedQuery<SearchRootFilesCountQuery>(searchRootFilesCountQuery, queryRef);
    filesCount = indexedFilesCount ?? 0;
  }

  return (
    <ExportContextProvider>
      <div>
        <Typography
          variant="h1"
          gutterBottom={true}
        >
          {t('Global search')}
        </Typography>
        <Box
          sx={{
            borderBottom: 1,
            borderColor: 'divider',
            marginBottom: 4,
          }}
        >
          <Tabs value={searchType}>
            <Tab
              component={Link}
              to={`/dashboard/search/knowledge/${keyword ?? ''}`}
              value='knowledge'
              label={t('Knowledge search')}
            />
            <Tab
              component={Link}
              to={`/dashboard/search/files/${keyword ?? ''}`}
              value='files'
              label={
                <div>
                  {t('Files search')}
                  {filesCount > 0 && (
                    <div style={{ position: 'absolute', fontSize: 10, right: 4, bottom: 4 }}>
                      {filesCount}
                    </div>
                  )}
                  <EEChip />
                </div>
              }
            />
          </Tabs>
        </Box>
        <Switch>
          <BoundaryRoute
            exact
            path="/dashboard/search/knowledge"
            render={(routeProps) => (
              <Search {...routeProps} />
            )}
          />
          <BoundaryRoute
            exact
            path="/dashboard/search/knowledge/:keyword"
            render={(routeProps) => (
              <Search {...routeProps} />
            )}
          />
          <BoundaryRoute
            exact
            path="/dashboard/search/files"
            render={(routeProps) => (
              <SearchIndexedFiles {...routeProps} />
            )}
          />
          <BoundaryRoute
            exact
            path="/dashboard/search/files/:keyword"
            render={(routeProps) => (
              <SearchIndexedFiles {...routeProps} />
            )}
          />
          <Redirect to="/dashboard/search/knowledge" />
        </Switch>
      </div>
    </ExportContextProvider>
  );
};

const SearchRoot = () => {
  const {
    platformModuleHelpers: { isFileIndexManagerEnable },
  } = useAuth();
  const fileSearchEnabled = isFileIndexManagerEnable();
  const { keyword } = useParams() as { keyword: string };
  const searchTerm = decodeSearchKeyword(keyword);

  const [queryRef, loadQuery] = useQueryLoader<SearchRootFilesCountQuery>(searchRootFilesCountQuery);
  const queryArgs = {
    search: searchTerm,
  };
  useEffect(() => {
    if (fileSearchEnabled) {
      loadQuery(queryArgs, { fetchPolicy: 'store-and-network' });
    }
  }, []);

  return (
      <SearchRootComponent queryRef={queryRef} />
  );
};

export default SearchRoot;
