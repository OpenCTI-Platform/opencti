import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import PublicStreamLines from '@components/data/stream/PublicStreamLines';
import PublicTaxiiLines from '@components/data/taxii/PublicTaxiiLines';
import PublicFeedLines from '@components/data/feeds/PublicFeedLines';
import React from 'react';
import { loadQuery, usePreloadedQuery } from 'react-relay';
import type { Theme } from '../../components/Theme';
import Message from '../../components/Message';
import { environment, fileUri } from '../../relay/environment';
import logo from '../../static/images/logo.png';
import { LoginRootPublicQuery } from '../__generated__/LoginRootPublicQuery.graphql';
import { rootPublicQuery } from '../LoginRoot';

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

  const { settings } = usePreloadedQuery<LoginRootPublicQuery>(
    rootPublicQuery,
    queryRef,
  );

  const loginLogo = theme.palette.mode === 'dark'
    ? settings.platform_theme_dark_logo_login
    : settings.platform_theme_light_logo_login;

  return (
    <>
      <Message />
      <div className={classes.container}>
        <img
          src={loginLogo && loginLogo.length > 0 ? loginLogo : fileUri(logo)}
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
