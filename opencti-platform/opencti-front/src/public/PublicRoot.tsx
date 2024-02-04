import React from 'react';
import CssBaseline from '@mui/material/CssBaseline';
import { StyledEngineProvider } from '@mui/material/styles';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import { loadQuery, usePreloadedQuery } from 'react-relay';
import PublicFeedLines from '@components/data/feeds/PublicFeedLines';
import { ConnectedThemeProvider } from '../components/AppThemeProvider';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import { environment, fileUri } from '../relay/environment';
import logoDark from '../static/images/logo_dark.png';
import logoLight from '../static/images/logo_light.png';
import type { Theme } from '../components/Theme';
import { rootPublicQuery } from './LoginRoot';
import PublicStreamLines from '../private/components/data/stream/PublicStreamLines';
import { LoginRootPublicQuery, LoginRootPublicQuery$data } from './__generated__/LoginRootPublicQuery.graphql';
import Message from '../components/Message';
import PublicTaxiiLines from '../private/components/data/taxii/PublicTaxiiLines';

const useStyles = makeStyles({
  container: {
    textAlign: 'center',
    margin: '0 auto',
    width: '70%',
    marginTop: '8rem',
  },
  logo: {
    width: 200,
    margin: '0px 0px 50px 0px',
  },
});

const PublicRootWithStyle = ({
  settings,
}: {
  settings: LoginRootPublicQuery$data['settings'];
}) => {
  const theme = useTheme<Theme>();
  const classes = useStyles();
  const loginLogo = theme.palette.mode === 'dark'
    ? settings.platform_theme_dark_logo_login
    : settings.platform_theme_light_logo_login;
  return (
    <>
      <Message />
      <div className={classes.container}>
        <img
          src={loginLogo && loginLogo.length > 0 ? loginLogo : fileUri(theme.palette.mode === 'dark' ? logoDark : logoLight)}
          alt="logo"
          className={classes.logo}
        />
        <PublicStreamLines />
        <PublicTaxiiLines />
        <PublicFeedLines />
      </div>
    </>
  );
};

const queryRef = loadQuery<LoginRootPublicQuery>(
  environment,
  rootPublicQuery,
  {},
);
const PublicRoot = () => {
  const { settings } = usePreloadedQuery<LoginRootPublicQuery>(
    rootPublicQuery,
    queryRef,
  );
  return (
    <StyledEngineProvider injectFirst={true}>
      <ConnectedThemeProvider settings={settings}>
        <CssBaseline />
        <ConnectedIntlProvider settings={settings}>
          <PublicRootWithStyle settings={settings} />
        </ConnectedIntlProvider>
      </ConnectedThemeProvider>
    </StyledEngineProvider>
  );
};

export default PublicRoot;
