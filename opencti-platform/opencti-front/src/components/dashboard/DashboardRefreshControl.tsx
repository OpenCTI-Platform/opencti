import RefreshIcon from '@mui/icons-material/Refresh';
import { Box } from '@mui/material';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Spinner } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useFormatter } from '../i18n';
import { useDashboardRefreshPendingState } from './DashboardRefreshContext';

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
  { value: 43200 },
  { value: 86400 },
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
  const { t_i18n } = useFormatter();
  const isQueryPending = useDashboardRefreshPendingState();
  const [isManualRefreshing, setIsManualRefreshing] = useState(false);
  const manualResetRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => {
    if (manualResetRef.current) {
      clearTimeout(manualResetRef.current);
      manualResetRef.current = null;
    }
  }, []);

  // Radix keys on strings only, so the numeric interval makes a round trip.
  const handleIntervalChange = (value: string) => {
    onIntervalChange(Number(value));
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
      case 43200:
        return t_i18n('12h');
      case 86400:
        return t_i18n('1d');
      default:
        return '';
    }
  }, [t_i18n]);

  const handleRefreshClick = () => {
    // Lock the button immediately: widget queries take a tick to register as
    // pending, so this short debounce bridges the gap until isQueryPending is true.
    setIsManualRefreshing(true);
    if (manualResetRef.current) clearTimeout(manualResetRef.current);
    manualResetRef.current = setTimeout(() => setIsManualRefreshing(false), 1200);
    onRefresh();
  };

  const spinning = isRefreshing || isManualRefreshing || isQueryPending;
  // Prevent spamming the refresh button until every widget has finished refreshing.
  const isRefreshDisabled = isManualRefreshing || isQueryPending;

  return (
    // NOT a MUI ButtonGroup any more, and that single swap is both halves of the report.
    <Box
      id="dashboard-refresh-control"
      sx={{ display: 'flex', alignItems: 'center', gap: 1 }}
    >
      <Button
        // The library's Spinner, not MUI's CircularProgress: `md` is the same 20px box, and
        // `inherit` keeps the button's own colour exactly as `color="inherit"` did.
        startIcon={spinning
          ? <Spinner size="md" tone="inherit" />
          : <RefreshIcon fontSize="small" />}
        onClick={handleRefreshClick}
        variant="secondary"
        disabled={isRefreshDisabled}
      >
        {t_i18n('Refresh')}
      </Button>
      <Select value={String(interval)} onValueChange={handleIntervalChange}>
        <SelectTrigger aria-label={t_i18n('Refresh interval')}>
          {/* Radix renders these children in place of the selected item, which is
              how the previous `renderValue` kept the trigger blank when off. */}
          <SelectValue>{interval === 0 ? '' : getIntervalLabel(interval)}</SelectValue>
        </SelectTrigger>
        <SelectContent aria-label={t_i18n('Refresh interval')}>
          {REFRESH_INTERVALS.map(({ value }) => (
            <SelectItem key={value} value={String(value)}>{getIntervalLabel(value)}</SelectItem>
          ))}
        </SelectContent>
      </Select>
    </Box>
  );
};

export default DashboardRefreshControl;
