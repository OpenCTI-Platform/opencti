import RefreshIcon from '@mui/icons-material/Refresh';
import { ButtonGroup, CircularProgress, MenuItem, Select, useTheme } from '@mui/material';
import Button from '@common/button/Button';
import type { SelectChangeEvent } from '@mui/material/Select';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useFormatter } from '../i18n';

type RefreshIntervalOption = {
  value: number;
};

const REFRESH_INTERVALS: ReadonlyArray<RefreshIntervalOption> = [
  { value: 0 },
  { value: 60 },
  { value: 300 },
  { value: 900 },
  { value: 1800 },
  { value: 3600 },
];

type DashboardRefreshControlProps = {
  onRefresh: () => void;
  interval: number;
  onIntervalChange: (value: number) => void;
  isRefreshing?: boolean;
};

const DashboardRefreshControl = ({
  onRefresh,
  interval,
  onIntervalChange,
  isRefreshing = false,
}: DashboardRefreshControlProps) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const primary = theme.palette.primary.main;
  const [isManualRefreshing, setIsManualRefreshing] = useState(false);
  const manualResetRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => {
    if (!manualResetRef.current) return;
    clearTimeout(manualResetRef.current);
    manualResetRef.current = null;
  }, []);

  const handleIntervalChange = (event: SelectChangeEvent<number>) => {
    onIntervalChange(Number(event.target.value));
  };

  const getIntervalLabel = useCallback((value: number) => {
    switch (value) {
      case 0:
        return t_i18n('Off');
      case 60:
        return t_i18n('1m');
      case 300:
        return t_i18n('5m');
      case 900:
        return t_i18n('15m');
      case 1800:
        return t_i18n('30m');
      case 3600:
        return t_i18n('1h');
      default:
        return '';
    }
  }, [t_i18n]);

  const handleRefreshClick = () => {
    setIsManualRefreshing(true);
    if (manualResetRef.current) clearTimeout(manualResetRef.current);
    manualResetRef.current = setTimeout(() => setIsManualRefreshing(false), 1200);
    onRefresh();
  };

  const spinning = isRefreshing || isManualRefreshing;

  return (
    <ButtonGroup size="small" variant="outlined">
      <Button
        startIcon={spinning ? <CircularProgress size={16} color="inherit" /> : <RefreshIcon />}
        onClick={handleRefreshClick}
        variant="secondary"
      >
        {t_i18n('Refresh')}
      </Button>
      <Select
        value={interval}
        onChange={handleIntervalChange}
        variant="outlined"
        size="small"
        displayEmpty
        renderValue={(selected) => (Number(selected) === 0
          ? ''
          : getIntervalLabel(Number(selected)))}
        sx={{
          minWidth: 0,
          borderRadius: '0 4px 4px 0',
          border: `1px solid ${primary}20`,
          '& .MuiSelect-select': {
            py: '5px',
            pl: 1,
            pr: '32px !important',
            minWidth: interval === 0 ? 0 : 26,
          },
          '& .MuiSelect-icon': { right: 8 },
        }}
      >
        {REFRESH_INTERVALS.map(({ value }) => (
          <MenuItem key={value} value={value}>{getIntervalLabel(value)}</MenuItem>
        ))}
      </Select>
    </ButtonGroup>
  );
};

export default DashboardRefreshControl;
