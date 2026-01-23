import { Box, Stack, SxProps } from '@mui/material';
import { useTheme } from '@mui/styles';
import { PropsWithChildren } from 'react';
import { Theme } from '../../../components/Theme';
import logoFiligranBaselineDark from '../../../static/images/logo_filigran_baseline_dark.svg';
import logoFiligranGradientDark from '../../../static/images/logo_filigran_gradient_dark.svg';
import logoFiligranBaselineLight from '../../../static/images/logo_filigran_baseline_light.svg';
import logoFiligranGradientLight from '../../../static/images/logo_filigran_gradient_light.svg';
import SystemBanners from '../SystemBanners';
import { LoginRootPublicQuery$data } from '../../__generated__/LoginRootPublicQuery.graphql';
import LoginLogo from './LoginLogo';

const LogoBaseline = () => {
  const theme = useTheme<Theme>();
  const logoBaseline = theme.palette.mode === 'dark'
    ? logoFiligranBaselineDark
    : logoFiligranBaselineLight;

  return (
    <img
      src={logoBaseline}
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
  const logoGradient = theme.palette.mode === 'dark'
    ? logoFiligranGradientDark
    : logoFiligranGradientLight;

  return (
    <img
      src={logoGradient}
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

  const isEnterpriseEdition = settings.platform_enterprise_edition_license_validated;
  const isWhitemarkEnable = settings.platform_whitemark && isEnterpriseEdition;

  const contentSx: SxProps = {
    minWidth: 500,
    overflow: 'hidden',
    background: theme.palette.designSystem.background.main,
  };

  const background = theme.palette.mode === 'dark'
    ? theme.palette.designSystem.gradient.background
    : 'linear-gradient(100.35deg, #EAEAED 0%, #FEFEFF 100%)';

  const asideSx: SxProps = {
    background,
    position: 'relative',
    overflow: 'hidden',
    boxShadow: '8px 0px 9px 0px #0000000F inset',
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
          {!isWhitemarkEnable && (
            <>
              <LogoBaseline />
              <LogoFiligran />
            </>
          )}
        </Box>
      </Stack>
    </>
  );
};

export default LoginLayout;
