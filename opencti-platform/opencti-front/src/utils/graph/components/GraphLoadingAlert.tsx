import React from 'react';
import Alert from '@mui/material/Alert';
import { useTheme } from '@mui/material/styles';
import LinearProgress from '@mui/material/LinearProgress';
import Typography from '@mui/material/Typography';
import type { Theme } from '../../../components/Theme';
import { useFormatter } from '../../../components/i18n';
import { useGraphContext } from '../GraphContext';

const GraphLoadingAlert = () => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const {
    graphState: {
      loadingCurrent = 1,
      loadingTotal = 1,
    },
  } = useGraphContext();

  const normaliseValue = (loadingCurrent * 100) / loadingTotal;

  return (
    <Alert
      severity="info"
      variant='outlined'
      sx={{
        position: 'absolute',
        zIndex: 99,
        top: theme.spacing(4),
        left: '50%',
        transform: 'translateX(-50%)',
        background: theme.palette.background.paper,
        overflow: 'hidden',
      }}
    >
      <Typography>
        {t_i18n('The graph is currently loading data.')}
      </Typography>
      <Typography sx={{ display: 'flex', justifyContent: 'space-between' }}>
        <span>{t_i18n('Data fetched:')}</span>
        <span>{loadingCurrent} / {loadingTotal}</span>
      </Typography>
      <LinearProgress
        sx={{
          position: 'absolute',
          bottom: 0,
          left: 0,
          right: 0,
        }}
        variant="determinate"
        value={normaliseValue}
      />
    </Alert>
  );
};

export default GraphLoadingAlert;
