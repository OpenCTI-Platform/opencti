import React from 'react';
import Box from '@mui/material/Box';
import Tab from '@mui/material/Tab';
import Tabs from '@mui/material/Tabs';
import { Link, Switch, useParams } from 'react-router-dom';
import Typography from '@mui/material/Typography';
import { BoundaryRoute } from '@components/Error';
import Search from '@components/Search';
import SearchIndexedFiles from '@components/search/SearchIndexedFiles';
import ExportContextProvider from '../../utils/ExportContextProvider';
import useAuth from '../../utils/hooks/useAuth';
import { useFormatter } from '../../components/i18n';

const SearchRoot = () => {
  const {
    platformModuleHelpers: { isFileIndexManagerEnable },
  } = useAuth();
  const { t } = useFormatter();
  const { scope } = useParams() as { scope: string };
  const { keyword } = useParams() as { keyword: string };
  let searchTerm = '';
  try {
    searchTerm = decodeURIComponent(keyword || '');
  } catch (e) {
    // Do nothing
  }
  const searchType = ['knowledge', 'files'].includes(scope) ? scope : 'knowledge';
  const fileSearchEnabled = isFileIndexManagerEnable();

  return (
    <ExportContextProvider>
      <div>
        <Typography
          variant="h1"
          gutterBottom={true}
        >
          {t('Global search')}{searchTerm ? ` : ${searchTerm}` : ''}
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
            {fileSearchEnabled && (
              <Tab
                component={Link}
                to={`/dashboard/search/files/${keyword ?? ''}`}
                value='files'
                label={t('Files search')}
              />
            )}
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
        </Switch>
      </div>
    </ExportContextProvider>
  );
};

export default SearchRoot;
