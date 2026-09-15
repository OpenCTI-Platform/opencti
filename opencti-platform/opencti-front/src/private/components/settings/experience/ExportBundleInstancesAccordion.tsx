import React, { FunctionComponent, useRef, useState } from 'react';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import FormControlLabel from '@mui/material/FormControlLabel';
import { Checkbox, Radio, RadioGroup, Input, Spinner } from '@filigran/design-system';
import Button from '@common/button/Button';
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
  selectedIds: string[];
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

  const loadEntities = (searchValue: string, cursor: string | null, append: boolean) => {
    setLoading(true);
    fetchQuery(config.query, {
      search: searchValue,
      count: PAGE_SIZE,
      cursor,
      ...(config.extraVariables ?? {}),
    })
      .toPromise()
      .then((response) => {
        const data = config.extractData(response);
        const newItems = (data?.edges ?? [])
          .map((edge) => edge?.node)
          .filter((node): node is InstanceItem => !!node)
          .map((node) => ({ id: node.id, name: node.name }));
        setItems((prev) => (append ? [...prev, ...newItems] : newItems));
        setHasNextPage(data?.pageInfo?.hasNextPage ?? false);
        setEndCursor(data?.pageInfo?.endCursor ?? null);
        setGlobalCount(data?.pageInfo?.globalCount ?? null);
      })
      .finally(() => {
        setLoading(false);
        setLoadedOnce(true);
      });
  };

  const handleExpand = (_event: React.SyntheticEvent, expanded: boolean) => {
    if (expanded && !loadedOnce) {
      loadEntities('', null, false);
    }
  };

  const handleSearchChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const value = event.target.value;
    setSearch(value);
    if (searchDebounce.current) clearTimeout(searchDebounce.current);
    searchDebounce.current = setTimeout(() => {
      loadEntities(value, null, false);
    }, 400);
  };

  const handleLoadMore = () => {
    if (hasNextPage && !loading) {
      loadEntities(search, endCursor, true);
    }
  };

  const handleModeRadioChange = (value: string) => {
    onModeChange(value as InstanceSelectionMode);
    if (value === 'partial' && !loadedOnce) {
      loadEntities('', null, false);
    }
  };

  const handleSummaryToggle = (checked: boolean | 'indeterminate') => {
    onModeChange(checked === true ? 'all' : 'none');
  };

  const summaryLabel = (() => {
    const label = t_i18n(config.label);
    if (mode === 'none') return label;
    if (mode === 'all') return `${label} (${t_i18n('all')})`;
    return `${label} (${selectedIds.length} ${t_i18n('selected')})`;
  })();

  return (
    <Accordion disableGutters sx={accordionSx} onChange={handleExpand}>
      <AccordionSummary expandIcon={<ExpandMoreOutlined />}>
        <FormControlLabel
          onClick={(e) => e.stopPropagation()}
          control={(
            <Checkbox
              checked={mode === 'partial' ? 'indeterminate' : mode !== 'none'}
              onCheckedChange={handleSummaryToggle}
              style={{ marginRight: 10, marginLeft: 10 }}
            />
          )}
          label={<Typography fontWeight="bold">{summaryLabel}</Typography>}
        />
      </AccordionSummary>
      <AccordionDetails sx={{ display: 'flex', flexDirection: 'column', paddingLeft: 5, marginTop: -1 }}>
        <RadioGroup value={mode === 'none' ? 'none' : mode} onValueChange={handleModeRadioChange}>
          <FormControlLabel value="all" control={<Radio value="all" style={{ marginRight: 10 }} />} label={t_i18n('Export all')} />
          <FormControlLabel value="partial" control={<Radio value="partial" style={{ marginRight: 10 }} />} label={t_i18n('Select specific elements')} />
        </RadioGroup>

        {mode === 'partial' && (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, mt: 1 }}>
            <Input
              value={search}
              onChange={handleSearchChange}
              placeholder={t_i18n('Search...')}
              startIcon={<SearchOutlined fontSize="small" />}
            />
            {globalCount !== null && (
              <Typography variant="caption" color="textSecondary">
                {`${selectedIds.length} ${t_i18n('selected')} / ${globalCount} ${t_i18n('total')}`}
              </Typography>
            )}
            <Box sx={{ maxHeight: 260, overflowY: 'auto', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              {items.map((item) => (
                <FormControlLabel
                  key={item.id}
                  control={(
                    <Checkbox
                      checked={selectedIds.includes(item.id)}
                      onCheckedChange={(checked) => onToggleId(item.id, checked === true)}
                      style={{ marginLeft: 15, marginRight: 10 }}
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
                  <Spinner size="sm" />
                </Box>
              )}
              {hasNextPage && !loading && (
                <Button size="small" onClick={handleLoadMore} sx={{ alignSelf: 'flex-start', mt: 2 }}>
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
