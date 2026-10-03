import React from 'react';
import { useNavigate } from 'react-router';
import { Paper, Text } from '@filigran/design-system';
import Stack from '@mui/material/Stack';
import { alpha } from '@mui/material/styles';
import LinkOffOutlinedIcon from '@mui/icons-material/LinkOffOutlined';
import Button from '@common/button/Button';
import { useFormatter } from 'src/components/i18n';

interface XtmHubDisconnectedBannerProps {
  unreachable?: boolean;
}

const XtmHubDisconnectedBanner = ({ unreachable = false }: XtmHubDisconnectedBannerProps) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();

  return (
    <Paper
      padding={24}
      className="flex items-center justify-between gap-2 flex-wrap"
      style={{
        marginTop: 24,
        background: 'linear-gradient(90deg, #061527 0%, #0d2b4a 100%)',
        border: 'none',
      }}
    >
      <Stack>
        <Stack direction="row" spacing={1.5} alignItems="center">
          <LinkOffOutlinedIcon sx={{ color: '#ffffff' }} fontSize="small" />
          <Text variant="content-base-bold" style={{ color: '#ffffff', fontSize: 15, fontFamily: '"Geologica", sans-serif' }}>
            {t_i18n('XTM Hub is disconnected')}
          </Text>
        </Stack>
        <Text variant="content-base" style={{ color: alpha('#ffffff', 0.7) }}>
          {unreachable
            ? t_i18n("XTM Hub is unreachable and connection can't be established")
            : t_i18n('Please connect your product so you can deploy resources')}
        </Text>
      </Stack>
      {!unreachable && (
        <Button onClick={() => navigate('/redirect/connect-xtm-hub')}>
          {t_i18n('Connect product to XTM Hub')}
        </Button>
      )}
    </Paper>
  );
};

export default XtmHubDisconnectedBanner;
