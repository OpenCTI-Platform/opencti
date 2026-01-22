import { Box, Stack, SxProps } from '@mui/material';
import { useTheme } from '@mui/styles';
import { PropsWithChildren } from 'react';
import { Theme } from '../../../components/Theme';
import logoFiligranBaseline from '../../../static/images/logo_filigran_baseline.svg';
import logoFiligranGradient from '../../../static/images/logo_filigran_gradient.svg';
import SystemBanners from '../SystemBanners';
import { LoginRootPublicQuery$data } from '../../__generated__/LoginRootPublicQuery.graphql';
import LoginLogo from './LoginLogo';

const LogoBaseline = () => {
  const theme = useTheme<Theme>();

  return (
    <img
      src={logoFiligranBaseline}
      alt="Made by Filigran logo"
      width={130}
      style={{
        userSelect: 'none',
        pointerEvents: 'none',
        position: 'absolute',
        bottom: theme.spacing(3),
        left: theme.spacing(3),
      }}
    />
  );
};

const LogoFiligran = () => {
  const theme = useTheme<Theme>();

  return (
    <img
      src={logoFiligranGradient}
      alt="Filigran Logo"
      style={{
        userSelect: 'none',
        pointerEvents: 'none',
        height: `calc(100% + ${theme.spacing(10)})`,
        position: 'absolute',
        top: theme.spacing(-5),
        right: theme.spacing(-5),
      }}
    />
  );
};

interface LoginLayoutProps extends PropsWithChildren {
  settings: LoginRootPublicQuery$data['publicSettings'];
}

const LoginLayout = ({ settings, children }: LoginLayoutProps) => {
  const theme = useTheme<Theme>();

  const contentSx: SxProps = {
    minWidth: 500,
    overflow: 'hidden',
    background: theme.palette.designSystem.background.main,
  };

  const asideSx: SxProps = {
    background: theme.palette.designSystem.gradient.background,
    position: 'relative',
    overflow: 'hidden',
    boxShadow: `8px 0px 9px 0px ${theme.palette.designSystem.background.main} inset`,
  };

  return (
    <>
      <SystemBanners settings={settings} />
      <Stack data-testid="login-page" direction="row" height="100%">
        <Stack
          flex={1}
          sx={contentSx}
          justifyContent="center"
          alignItems="center"
          gap={4}
        >
          <LoginLogo data={settings} />
          {children}
        </Stack>
        <Box flex={2} sx={asideSx}>
          <LogoBaseline />
          <LogoFiligran />
        </Box>
      </Stack>
    </>
  );
};

export default LoginLayout;
