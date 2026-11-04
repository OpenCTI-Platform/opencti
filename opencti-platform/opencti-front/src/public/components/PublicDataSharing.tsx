import Box from '@mui/material/Box';
import { useTheme } from '@mui/material/styles';
import PublicStreamLines from '@components/data/stream/PublicStreamLines';
import PublicTaxiiLines from '@components/data/taxii/PublicTaxiiLines';
import PublicFeedLines from '@components/data/feeds/PublicFeedLines';
import React from 'react';
import { loadQuery, usePreloadedQuery } from 'react-relay';
import type { Theme } from '../../components/Theme';
import { environment } from '../../relay/environment';
import { LoginRootPublicQuery } from '../__generated__/LoginRootPublicQuery.graphql';
import { rootPublicQuery } from '../LoginRoot';
import logoLight from '../../static/images/logo_light.png';
import logoDark from '../../static/images/logo_dark.png';

const queryRef = loadQuery<LoginRootPublicQuery>(
  environment,
  rootPublicQuery,
  {},
);

const PublicDataSharing = () => {
  const theme = useTheme<Theme>();

  const { publicSettings: settings } = usePreloadedQuery<LoginRootPublicQuery>(
    rootPublicQuery,
    queryRef,
  );

  const loginLogo = settings.platform_theme?.theme_logo_login || theme.logo;

  return (
    <>
      <Box
        sx={{
          textAlign: 'center',
          margin: '0 auto',
          width: '70%',
          marginTop: '8rem',
        }}
      >
        <Box
          component="img"
          src={loginLogo && loginLogo.length > 0 ? loginLogo : theme.palette.mode === 'dark' ? logoDark : logoLight}
          alt="logo"
          sx={{ width: 200, margin: '0px 0px 50px 0px' }}
        />
        <PublicStreamLines />
        <PublicTaxiiLines />
        <PublicFeedLines />
      </Box>
    </>
  );
};

export default PublicDataSharing;
