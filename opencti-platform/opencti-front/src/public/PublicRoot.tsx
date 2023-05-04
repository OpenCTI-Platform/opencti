import CssBaseline from '@mui/material/CssBaseline';
import { StyledEngineProvider } from '@mui/material/styles';
import { useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import React from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import { ConnectedThemeProvider } from '../components/AppThemeProvider';
import Loader, { LoaderVariant } from '../components/Loader';
import Message from '../components/Message';
import { Theme } from '../components/Theme';
import { PublicStreamLinesQuery } from '../private/components/data/stream/__generated__/PublicStreamLinesQuery.graphql';
import PublicStreamLines, { publicStreamLinesQuery } from '../private/components/data/stream/PublicStreamLines';
import { fileUri } from '../relay/environment';
import logo from '../static/images/logo.png';
import useQueryLoading from '../utils/hooks/useQueryLoading';
import { LoginRootPublicQuery, LoginRootPublicQuery$data } from './__generated__/LoginRootPublicQuery.graphql';
import { rootPublicQuery } from './LoginRoot';

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

  const queryRef = useQueryLoading<PublicStreamLinesQuery>(publicStreamLinesQuery, {});

  return (
    <>
      <Message />
      <div className={classes.container}>
        <img
          src={loginLogo && loginLogo.length > 0 ? loginLogo : fileUri(logo)}
          alt="logo"
          className={classes.logo}
        />
        {queryRef && (
          <React.Suspense
            fallback={<Loader variant={LoaderVariant.inElement} />}
          >
            <PublicStreamLines queryRef={queryRef} />
          </React.Suspense>
        )}
      </div>
    </>
  );
};

const PublicRootComponent = ({ queryRef }: { queryRef: PreloadedQuery<LoginRootPublicQuery> }) => {
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

const PublicRoot = () => {
  const queryRef = useQueryLoading<LoginRootPublicQuery>(rootPublicQuery, {});
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <PublicRootComponent queryRef={queryRef} />
        </React.Suspense>
      )}
    </>
  );
};

export default PublicRoot;
