import React, { Suspense } from 'react';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { Link, Route, Routes, useLocation } from 'react-router-dom';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import makeStyles from '@mui/styles/makeStyles';
import type { Theme } from '../../../../../components/Theme';
import SearchLogOverview from './summary/SearchLogOverview';
import SearchLog from './detailed/SearchLog';
import { useFormatter } from '../../../../../components/i18n';
import Security from '../../../../../utils/Security';
import { SETTINGS_SECURITYACTIVITY } from '../../../../../utils/hooks/useGranted';
import ActivityMenu from '../../ActivityMenu';
import Breadcrumbs from '../../../../../components/Breadcrumbs';
import { getCurrentTab } from '../../../../../utils/tabUtils';
import Loader, { LoaderVariant } from '../../../../../components/Loader';

const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: 0,
  },
}));

const RootSearchLogs = () => {
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const { forceUpdate } = useForceUpdate();

  return (
    <Security
      needs={[SETTINGS_SECURITYACTIVITY]}
      placeholder={(
        <span>{t_i18n(
          'You do not have any access to the audit activity of this OpenCTI instance.',
        )}
        </span>
      )}
    >
      <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
        <div className={classes.container} data-testid="search-log-page">
          <ActivityMenu />
          <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Searches') }, {
            label: t_i18n('Search Logs'),
            current: true,
          }]}
          />
          <Box
            sx={{
              borderBottom: 1,
              borderColor: 'divider',
              marginBottom: 3,
            }}
          >
            <Tabs
              value={getCurrentTab(location.pathname, 'search', '/dashboard/settings/activity/searches')}
            >
              <Tab
                component={Link}
                to="/dashboard/settings/activity/searches"
                value="/dashboard/settings/activity/searches"
                label={t_i18n('Overview')}
              />
              <Tab
                component={Link}
                to="/dashboard/settings/activity/searches/details"
                value="/dashboard/settings/activity/searches/details"
                label={t_i18n('Details')}
              />
            </Tabs>
          </Box>
          <Routes>
            <Route
              path="/"
              element={(
                <SearchLogOverview />
              )}
            />
            <Route
              path="/details"
              element={(
                <div key={forceUpdate}>
                  <SearchLog />
                </div>
              )}
            />
          </Routes>
        </div>
      </Suspense>
    </Security>
  );
};

export default RootSearchLogs;
