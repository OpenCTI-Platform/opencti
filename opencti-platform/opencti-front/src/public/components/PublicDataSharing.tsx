import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import PublicStreamLines from '@components/data/stream/PublicStreamLines';
import PublicTaxiiLines from '@components/data/taxii/PublicTaxiiLines';
import PublicFeedLines from '@components/data/feeds/PublicFeedLines';
import React from 'react';
import { loadQuery, usePreloadedQuery } from 'react-relay';
import type { Theme } from '../../components/Theme';
import { environment, fileUri } from '../../relay/environment';
import { LoginRootPublicQuery } from '../__generated__/LoginRootPublicQuery.graphql';
import { rootPublicQuery } from '../LoginRoot';
import logoLight from '../../static/images/logo_light.png';
import logoDark from '../../static/images/logo_dark.png';
import { deserializeThemeManifest } from '../../private/components/settings/themes/ThemeType';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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

const queryRef = loadQuery<LoginRootPublicQuery>(
  environment,
  rootPublicQuery,
  {},
);

const PublicDataSharing = () => {
  const theme = useTheme<Theme>();
  const classes = useStyles();

  const { settings, themes } = usePreloadedQuery<LoginRootPublicQuery>(
    rootPublicQuery,
    queryRef,
  );

  const defaultTheme = themes?.edges?.filter((node) => !!node)
    .map(({ node }) => ({ ...node }))
    .filter(({ name }) => name === settings.platform_theme)?.[0];
  const loginLogo = deserializeThemeManifest(defaultTheme?.manifest)
    .theme_logo_login;

  return (
    <>
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

export default PublicDataSharing;
