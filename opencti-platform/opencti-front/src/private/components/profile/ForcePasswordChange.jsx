import React from 'react';
import { Box, Stack, useTheme } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import PasswordPolicies from '../common/form/PasswordPolicies';
import { useFormatter } from '../../../components/i18n';
import { MESSAGING$ } from '../../../relay/environment';
import ForcePasswordChangeForm from '../../../components/ForcePasswordChangeForm';
import logoDark from '../../../static/images/logo_text_dark.png';
import logoLight from '../../../static/images/logo_text_light.png';
import logoFiligranBaselineDark from '../../../static/images/logo_filigran_baseline_dark.svg';
import logoFiligranGradientDark from '../../../static/images/logo_filigran_gradient_dark.svg';
import logoFiligranBaselineLight from '../../../static/images/logo_filigran_baseline_light.svg';
import logoFiligranGradientLight from '../../../static/images/logo_filigran_gradient_light.svg';

const ForcePasswordChange = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();

  const handleSuccess = () => {
    MESSAGING$.notifySuccess(t_i18n('The password has been updated'));
    navigate('/dashboard', { replace: true });
  };

  return (
    <Stack direction="row" height="100vh">
      <Stack
        flex={1}
        justifyContent="center"
        alignItems="center"
        gap={4}
        sx={{
          minWidth: 500,
          overflow: 'hidden',
          background: theme.palette.designSystem?.background?.main ?? theme.palette.background.default,
          boxShadow: '8px 0px 9px 0px #0000002F',
          zIndex: 2,
        }}
      >
        <img
          src={theme.palette.mode === 'dark' ? logoDark : logoLight}
          alt="OpenCTI Logo"
          width={180}
        />
        <Stack gap={1} sx={{ width: 500 }}>
          <Box
            sx={{
              background: theme.palette.background.paper,
              borderRadius: 1,
              padding: theme.spacing(3),
            }}
          >
            <ForcePasswordChangeForm
              onSuccess={handleSuccess}
              renderPolicies={(password) => (
                <Box sx={{ width: '100%', mt: 2 }}>
                  <PasswordPolicies value={password} />
                </Box>
              )}
            />
          </Box>
        </Stack>
      </Stack>
      <Box
        flex={1}
        sx={{
          background: theme.palette.mode === 'dark'
            ? 'linear-gradient(100deg, #050A14 0%, #0C1728 100%)'
            : 'linear-gradient(100deg, #EAEAED 0%, #FEFEFF 100%)',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        <img
          src={theme.palette.mode === 'dark' ? logoFiligranGradientDark : logoFiligranGradientLight}
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
        <img
          src={theme.palette.mode === 'dark' ? logoFiligranBaselineDark : logoFiligranBaselineLight}
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
      </Box>
    </Stack>
  );
};

export default ForcePasswordChange;
