import React, { FunctionComponent, ReactNode, Suspense, useEffect } from 'react';
import Box from '@mui/material/Box';
import Tab from '@mui/material/Tab';
import Tabs from '@mui/material/Tabs';
import { Link, useLocation, useParams } from 'react-router-dom';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Badge from '@mui/material/Badge';
import { useTheme } from '@mui/styles';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { useFormatter } from '../../../components/i18n';
import { decodeSearchKeyword } from '../../../utils/SearchUtils';
import useAuth from '../../../utils/hooks/useAuth';
import { SearchContainerQueryFilesCountQuery } from './__generated__/SearchContainerQueryFilesCountQuery.graphql';
import Breadcrumbs from '../../../components/Breadcrumbs';
import type { Theme } from '../../../components/Theme';
import Loader from '../../../components/Loader';

const searchContainerQueryFilesCountQuery = graphql`
  query SearchContainerQueryFilesCountQuery($search: String) {
    indexedFilesCount(search: $search)
  }
`;

interface SearchRootComponentProps {
  children: ReactNode;
  filesCount?: number;
}

const SearchContainer: FunctionComponent<SearchRootComponentProps> = ({ children, filesCount = 0 }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { keyword } = useParams() as { keyword: string };
  const location = useLocation();
  let searchType = 'knowledge';
  if (location.pathname.includes('/files')) {
    searchType = 'files';
  }
  return (
    <ExportContextProvider>
      <Breadcrumbs elements={[{ label: t_i18n('Search') }, { label: t_i18n('Advanced search'), current: true }]} />
      <Box
        sx={{
          borderBottom: 1,
          borderColor: 'divider',
          marginBottom: 3,
          marginTop: theme.spacing(-1),
        }}
      >
        <Tabs id="tabs-container" value={searchType}>
          <Tab
            component={Link}
            to={`/dashboard/search/knowledge/${keyword ?? ''}`}
            value="knowledge"
            label={t_i18n('Knowledge search')}
          />
          <Tab
            component={Link}
            to={`/dashboard/search/files/${keyword ?? ''}`}
            value="files"
            label={
              <Badge badgeContent={filesCount} color="primary">
                <div style={{ padding: '0px 12px', display: 'flex' }}>{t_i18n('Files search')}<EEChip /></div>
              </Badge>
            }
          />
        </Tabs>
      </Box>
      <Suspense fallback={<Loader />}>
        {children}
      </Suspense>
    </ExportContextProvider>
  );
};

interface SearchContainerQueryWithRefProps {
  children: ReactNode
  queryRef: PreloadedQuery<SearchContainerQueryFilesCountQuery>;
}

const SearchContainerQueryWithRef: FunctionComponent<SearchContainerQueryWithRefProps> = ({ queryRef, children }) => {
  const { indexedFilesCount } = usePreloadedQuery<SearchContainerQueryFilesCountQuery>(searchContainerQueryFilesCountQuery, queryRef);
  const filesCount = indexedFilesCount ?? 0;
  return (
    <SearchContainer filesCount={filesCount}>
      {children}
    </SearchContainer>
  );
};

interface SearchContainerQueryProps {
  children: ReactNode
}

const SearchContainerQuery = ({ children }: SearchContainerQueryProps) => {
  const {
    platformModuleHelpers: { isFileIndexManagerEnable },
  } = useAuth();
  const fileSearchEnabled = isFileIndexManagerEnable();
  const { keyword } = useParams() as { keyword: string };
  const searchTerm = decodeSearchKeyword(keyword);

  const [queryRef, loadQuery] = useQueryLoader<SearchContainerQueryFilesCountQuery>(searchContainerQueryFilesCountQuery);
  const queryArgs = {
    search: searchTerm,
  };
  useEffect(() => {
    if (fileSearchEnabled) {
      loadQuery(queryArgs, { fetchPolicy: 'store-and-network' });
    }
  }, []);

  return (
    <>
      {(fileSearchEnabled) ? (
        <>
          {queryRef ? (
            <SearchContainerQueryWithRef queryRef={queryRef}>
              {children}
            </SearchContainerQueryWithRef>
          ) : (<Loader />) }
        </>
      ) : (
        <SearchContainer>
          {children}
        </SearchContainer>
      )}
    </>
  );
};

export default SearchContainerQuery;
