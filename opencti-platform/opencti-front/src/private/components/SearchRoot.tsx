import React from 'react';
import Box from '@mui/material/Box';
import Tab from '@mui/material/Tab';
import Tabs from '@mui/material/Tabs';
import { Link, Redirect, Switch, useParams } from 'react-router-dom';
import Typography from '@mui/material/Typography';
import { BoundaryRoute } from '@components/Error';
import Search from '@components/Search';
import SearchIndexedFiles from '@components/search/SearchIndexedFiles';
import EEChip from '@components/common/entreprise_edition/EEChip';
import ExportContextProvider from '../../utils/ExportContextProvider';
import { useFormatter } from '../../components/i18n';

const SearchRoot = () => {
  const { t } = useFormatter();
  const { scope } = useParams() as { scope: string };
  const { keyword } = useParams() as { keyword: string };
  const searchType = ['knowledge', 'files'].includes(scope) ? scope : 'knowledge';

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
              label={<div>{t('Files search')}<EEChip /></div>}
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

export default SearchRoot;
