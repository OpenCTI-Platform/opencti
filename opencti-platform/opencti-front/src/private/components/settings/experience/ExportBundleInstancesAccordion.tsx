import React, { FunctionComponent, useCallback, useRef, useState } from 'react';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import Checkbox from '@mui/material/Checkbox';
import FormControlLabel from '@mui/material/FormControlLabel';
import Radio from '@mui/material/Radio';
import RadioGroup from '@mui/material/RadioGroup';
import TextField from '@mui/material/TextField';
import CircularProgress from '@mui/material/CircularProgress';
import Button from '@mui/material/Button';
import InputAdornment from '@mui/material/InputAdornment';
import ExpandMoreOutlined from '@mui/icons-material/ExpandMoreOutlined';
import SearchOutlined from '@mui/icons-material/SearchOutlined';
import type { SxProps } from '@mui/material/styles';
import { useFormatter } from 'src/components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import type { ExportInstanceConfig, InstanceItem } from './exportBundleInstances';

export type InstanceSelectionMode = 'none' | 'all' | 'partial';

const PAGE_SIZE = 25;

interface ExportBundleInstancesAccordionProps {
  config: ExportInstanceConfig;
  mode: InstanceSelectionMode;
  selectedIds: Set<string>;
  onModeChange: (mode: InstanceSelectionMode) => void;
  onToggleId: (id: string, checked: boolean) => void;
  accordionSx: SxProps;
}

const ExportBundleInstancesAccordion: FunctionComponent<ExportBundleInstancesAccordionProps> = ({
  config,
  mode,
  selectedIds,
  onModeChange,
  onToggleId,
  accordionSx,
}) => {
  const { t_i18n } = useFormatter();

  const [items, setItems] = useState<InstanceItem[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);
  const [hasNextPage, setHasNextPage] = useState(false);
  const [endCursor, setEndCursor] = useState<string | null>(null);
  const [globalCount, setGlobalCount] = useState<number | null>(null);
  const [loadedOnce, setLoadedOnce] = useState(false);

  const searchDebounce = useRef<ReturnType<typeof setTimeout> | null>(null);

  const runFetch = useCallback((searchValue: string, cursor: string | null, append: boolean) => {
    setLoading(true);
    fetchQuery(config.query, {
      search: searchValue,
      count: PAGE_SIZE,
      cursor,
      ...(config.extraVariables ?? {}),
    })
      .toPromise()
      .then((raw) => {
        const connection = config.extractConnection(raw);
        const newItems = (connection?.edges ?? [])
          .map((edge) => edge?.node)
          .filter((node): node is InstanceItem => !!node)
          .map((node) => ({ id: node.id, name: node.name }));
        setItems((prev) => (append ? [...prev, ...newItems] : newItems));
        setHasNextPage(connection?.pageInfo?.hasNextPage ?? false);
        setEndCursor(connection?.pageInfo?.endCursor ?? null);
        setGlobalCount(connection?.pageInfo?.globalCount ?? null);
      })
      .finally(() => {
        setLoading(false);
        setLoadedOnce(true);
      });
  }, [config]);

  const handleExpand = (_event: React.SyntheticEvent, expanded: boolean) => {
    if (expanded && !loadedOnce) {
      runFetch('', null, false);
    }
  };

  const handleSearchChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const value = event.target.value;
    setSearch(value);
    if (searchDebounce.current) clearTimeout(searchDebounce.current);
    searchDebounce.current = setTimeout(() => {
      runFetch(value, null, false);
    }, 400);
  };

  const handleLoadMore = () => {
    if (hasNextPage && !loading) {
      runFetch(search, endCursor, true);
    }
  };

  const handleModeRadioChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    onModeChange(event.target.value as InstanceSelectionMode);
    if (event.target.value === 'partial' && !loadedOnce) {
      runFetch('', null, false);
    }
  };

  const handleSummaryToggle = (event: React.ChangeEvent<HTMLInputElement>) => {
    onModeChange(event.target.checked ? 'all' : 'none');
  };

  const summaryLabel = (() => {
    const label = t_i18n(config.label);
    if (mode === 'none') return label;
    if (mode === 'all') return `${label} (${t_i18n('all')})`;
    return `${label} (${selectedIds.size} ${t_i18n('selected')})`;
  })();

  return (
    <Accordion disableGutters sx={accordionSx} onChange={handleExpand}>
      <AccordionSummary expandIcon={<ExpandMoreOutlined />}>
        <FormControlLabel
          onClick={(e) => e.stopPropagation()}
          control={(
            <Checkbox
              checked={mode !== 'none'}
              indeterminate={mode === 'partial'}
              onChange={handleSummaryToggle}
            />
          )}
          label={<Typography fontWeight="bold">{summaryLabel}</Typography>}
        />
      </AccordionSummary>
      <AccordionDetails sx={{ display: 'flex', flexDirection: 'column', paddingLeft: 5, paddingTop: 0, marginTop: -1 }}>
        <RadioGroup value={mode === 'none' ? 'none' : mode} onChange={handleModeRadioChange}>
          <FormControlLabel value="all" control={<Radio size="small" />} label={t_i18n('Export all')} />
          <FormControlLabel value="partial" control={<Radio size="small" />} label={t_i18n('Select specific elements')} />
        </RadioGroup>

        {mode === 'partial' && (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, mt: 1 }}>
            <TextField
              value={search}
              onChange={handleSearchChange}
              placeholder={t_i18n('Search...')}
              variant="standard"
              fullWidth
              slotProps={{
                input: {
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchOutlined fontSize="small" />
                    </InputAdornment>
                  ),
                },
              }}
            />
            {globalCount !== null && (
              <Typography variant="caption" color="textSecondary">
                {`${selectedIds.size} ${t_i18n('selected')} / ${globalCount} ${t_i18n('total')}`}
              </Typography>
            )}
            <Box sx={{ maxHeight: 260, overflowY: 'auto', display: 'flex', flexDirection: 'column' }}>
              {items.map((item) => (
                <FormControlLabel
                  key={item.id}
                  control={(
                    <Checkbox
                      size="small"
                      checked={selectedIds.has(item.id)}
                      onChange={(e) => onToggleId(item.id, e.target.checked)}
                    />
                  )}
                  label={item.name}
                />
              ))}
              {loadedOnce && items.length === 0 && !loading && (
                <Typography variant="body2" color="textSecondary" sx={{ py: 1 }}>
                  {t_i18n('No element found')}
                </Typography>
              )}
              {loading && (
                <Box sx={{ display: 'flex', justifyContent: 'center', py: 1 }}>
                  <CircularProgress size={20} />
                </Box>
              )}
              {hasNextPage && !loading && (
                <Button size="small" onClick={handleLoadMore} sx={{ alignSelf: 'flex-start' }}>
                  {t_i18n('Load more')}
                </Button>
              )}
            </Box>
          </Box>
        )}
      </AccordionDetails>
    </Accordion>
  );
};

export default ExportBundleInstancesAccordion;
