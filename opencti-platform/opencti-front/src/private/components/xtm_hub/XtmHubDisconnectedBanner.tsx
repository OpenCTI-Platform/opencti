import React from 'react';
import { useNavigate } from 'react-router-dom';
import Paper from '@mui/material/Paper';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
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
      variant="outlined"
      sx={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 2,
        flexWrap: 'wrap',
        padding: '24px 20px',
        borderRadius: 1,
        marginTop: 3,
        background: 'linear-gradient(90deg, #061527 0%, #0d2b4a 100%)',
        border: 'none',
      }}
    >
      <Stack>
        <Stack direction="row" spacing={1.5} alignItems="center">
          <LinkOffOutlinedIcon sx={{ color: '#ffffff' }} fontSize="small" />
          <Typography sx={{ color: '#ffffff', fontWeight: 700, fontSize: 15, fontFamily: '"Geologica", sans-serif' }}>
            {t_i18n('XTM Hub is disconnected')}
          </Typography>
        </Stack>
        <Typography variant="body2" sx={{ color: alpha('#ffffff', 0.7) }}>
          {unreachable
            ? t_i18n("XTM Hub is unreachable and connection can't be established")
            : t_i18n('Please connect your product so you can deploy resources')}
        </Typography>
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
