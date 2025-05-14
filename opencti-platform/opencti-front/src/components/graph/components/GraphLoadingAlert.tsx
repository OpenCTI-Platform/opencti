import React, { useEffect, useRef, useState } from 'react';
import Alert from '@mui/material/Alert';
import { useTheme } from '@mui/material/styles';
import LinearProgress from '@mui/material/LinearProgress';
import Typography from '@mui/material/Typography';
import type { Theme } from '../../Theme';
import { useFormatter } from '../../i18n';
import { useGraphContext } from '../GraphContext';

const MIN_DISPLAY_MS = 1500;

const GraphLoadingAlert = () => {
  const startTime = useRef<number>(undefined);
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const [showAlert, setShowAlert] = useState(false);

  const {
    graphState: {
      loadingCurrent,
      loadingTotal,
    },
  } = useGraphContext();

  useEffect(() => {
    const isLoadingData = loadingCurrent && loadingTotal && loadingCurrent < loadingTotal;

    if (!isLoadingData) {
      if (startTime.current) {
        const durationDisplay = Date.now() - startTime.current;
        const durationDelta = MIN_DISPLAY_MS - durationDisplay;
        startTime.current = undefined;
        // Ensure the alert is displayed long enough to let understand
        // the user what is going on and avoid blink effect.
        setTimeout(() => {
          setShowAlert(false);
        }, durationDelta < 0 ? 0 : durationDelta);
      }
    } else {
      setShowAlert(true);
      if (!startTime.current) {
        startTime.current = Date.now();
      }
    }
  }, [loadingCurrent, loadingTotal]);

  if (!showAlert || !loadingTotal || !loadingCurrent) {
    return null;
  }

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
