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
import { hasCustomColor } from '../../../utils/theme';
import { getLoginAsideType } from '../../../private/components/settings/themes/theme-utils';

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
        zIndex: 2,
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

  const loginAsideType = getLoginAsideType({
    theme_login_aside_color: settings.platform_theme?.theme_login_aside_color,
    theme_login_aside_gradient_start: settings.platform_theme?.theme_login_aside_gradient_start,
    theme_login_aside_gradient_end: settings.platform_theme?.theme_login_aside_gradient_end,
    theme_login_aside_image: settings.platform_theme?.theme_login_aside_image,
  });

  const getAsideBackground = () => {
    if (loginAsideType === 'color') {
      return settings.platform_theme?.theme_login_aside_color;
    }

    if (loginAsideType === 'gradient') {
      return `linear-gradient(135deg, ${settings.platform_theme?.theme_login_aside_gradient_start} 0%, ${settings.platform_theme?.theme_login_aside_gradient_end} 100%)`;
    }

    if (loginAsideType === 'image') {
      return `url(${settings.platform_theme?.theme_login_aside_image})`;
    }
    // fallback to default
    return theme.palette.mode === 'dark'
      ? 'linear-gradient(100deg, #050A14 0%, #0C1728 100%)'
      : 'linear-gradient(100deg, #EAEAED 0%, #FEFEFF 100%)';
  };

  const hasCustomBackground = hasCustomColor(theme, 'theme_background');
  const backgroundContent = hasCustomBackground
    ? theme.palette.background.default
    : theme.palette.designSystem.background.main;

  const contentSx: SxProps = {
    minWidth: 500,
    overflow: 'hidden',
    background: backgroundContent,
    boxShadow: '8px 0px 9px 0px #0000000F',
    zIndex: 2,
  };

  console.log('settings.platform_theme?', settings.platform_theme);

  const asideSx: SxProps = {
    background: getAsideBackground(),
    backgroundSize: loginAsideType === 'image' ? 'cover' : undefined,
    backgroundPosition: loginAsideType === 'image' ? 'center' : undefined,
    position: 'relative',
    overflow: 'hidden',
  };
  // const background = theme.palette.mode === 'dark'
  //   ? 'linear-gradient(100deg, #050A14 0%, #0C1728 100%);'
  //   : 'linear-gradient(100deg, #EAEAED 0%, #FEFEFF 100%)';

  // const asideSx: SxProps = {
  //   background,
  //   position: 'relative',
  //   overflow: 'hidden',
  // };

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
        <Box flex={1} sx={asideSx}>
          {!isWhitemarkEnable && loginAsideType === '' && (
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
