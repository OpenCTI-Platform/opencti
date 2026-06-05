import RefreshIcon from '@mui/icons-material/Refresh';
import { ButtonGroup, CircularProgress, MenuItem, Select, useTheme } from '@mui/material';
import Button from '@common/button/Button';
import type { SelectChangeEvent } from '@mui/material/Select';
import { useRef, useState } from 'react';
import { useFormatter } from '../i18n';

type RefreshIntervalOption = {
  label: string;
  value: number;
};

const REFRESH_INTERVALS: ReadonlyArray<RefreshIntervalOption> = [
  { label: 'Off', value: 0 },
  { label: '1m', value: 60 },
  { label: '5m', value: 300 },
  { label: '15m', value: 900 },
  { label: '30m', value: 1800 },
  { label: '1h', value: 3600 },
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

  const handleIntervalChange = (event: SelectChangeEvent<number>) => {
    onIntervalChange(Number(event.target.value));
  };

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
          : REFRESH_INTERVALS.find(({ value }) => value === Number(selected))?.label ?? '')}
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
        {REFRESH_INTERVALS.map(({ label, value }) => (
          <MenuItem key={value} value={value}>{label}</MenuItem>
        ))}
      </Select>
    </ButtonGroup>
  );
};

export default DashboardRefreshControl;
