import { Box, Stack, Typography } from '@mui/material';
import { PropsWithChildren } from 'react';
import SystemBanners from '../SystemBanners';
import { LoginRootPublicQuery$data } from '../../__generated__/LoginRootPublicQuery.graphql';
import LoginLogo from './LoginLogo';

const LOGIN_ASIDE_COLOR = '#1A2D7A';
const LOGIN_TEXT_COLOR = '#111827';

const loginPanelInputSx = {
  '& .MuiInputBase-root': {
    color: LOGIN_TEXT_COLOR,
  },
  '& .MuiInputBase-input': {
    color: LOGIN_TEXT_COLOR,
    WebkitTextFillColor: LOGIN_TEXT_COLOR,
  },
  '& .MuiInputBase-input:-webkit-autofill, & .MuiInputBase-input:-webkit-autofill:hover, & .MuiInputBase-input:-webkit-autofill:focus': {
    WebkitTextFillColor: LOGIN_TEXT_COLOR,
    WebkitBoxShadow: '0 0 0 100px #FFFFFF inset',
    transition: 'background-color 5000s ease-in-out 0s',
  },
};

interface LoginLayoutProps extends PropsWithChildren {
  settings: LoginRootPublicQuery$data['publicSettings'];
}

const LoginLayout = ({ settings, children }: LoginLayoutProps) => {
  const currentYear = new Date().getFullYear();

  return (
    <>
      <SystemBanners settings={settings} />
      <Stack data-testid="login-page" direction="row" height="100%">
        <Box
          flex={3}
          sx={{
            position: 'relative',
            display: 'flex',
            flexDirection: 'column',
            backgroundColor: '#FFFFFF',
            color: LOGIN_TEXT_COLOR,
            minWidth: 0,
            ...loginPanelInputSx,
          }}
        >
          <Box sx={{ p: 4, pb: 0 }}>
            <LoginLogo data={settings} />
          </Box>

          <Stack
            flex={1}
            justifyContent="center"
            alignItems="center"
            sx={{ px: 4, py: 6 }}
          >
            {children}
          </Stack>

          <Typography
            variant="body2"
            sx={{
              position: 'absolute',
              bottom: 24,
              left: 32,
              color: '#9CA3AF',
              fontSize: 13,
            }}
          >
            {`© ResaaCTIP ${currentYear}`}
          </Typography>
        </Box>

        <Box
          flex={2}
          sx={{
            backgroundColor: LOGIN_ASIDE_COLOR,
            minWidth: 0,
          }}
        />
      </Stack>
    </>
  );
};

export default LoginLayout;
