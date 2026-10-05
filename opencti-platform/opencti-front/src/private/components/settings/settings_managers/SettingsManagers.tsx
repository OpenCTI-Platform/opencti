import { SearchField } from '@filigran/design-system';
import Box from '@mui/material/Box';
// fds:keep-mui the library ButtonGroupItem is a 36x36 glyph-only square; this filter needs labelled segments with counts (LIBRARY-FEEDBACK #63)
import ToggleButton from '@mui/material/ToggleButton';
// fds:keep-mui the library ButtonGroupItem is a 36x36 glyph-only square; this filter needs labelled segments with counts (LIBRARY-FEEDBACK #63)
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import React, { useState } from 'react';
import Button from '../../../../components/common/button/Button';
import Card from '../../../../components/common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import type { Theme } from '../../../../components/Theme';
import EEChip from '../../common/entreprise_edition/EEChip';
import SettingsOverline from '../settings_platform/SettingsOverline';
import { countManagers, filterManagers, groupManagers, ManagerItem, ManagerStatusFilter, PlatformModule, toManagerItems } from './settingsManagersUtils';

interface SettingsManagersProps {
  modules: ReadonlyArray<PlatformModule>;
  isEnterpriseEditionValid: boolean;
}

const STATUS_FILTERS: ManagerStatusFilter[] = ['all', 'enabled', 'disabled', 'unlicensed'];
// Heights are multiples of the grid row unit so a group's span is exact.
const GRID_ROW_UNIT = 8;
const HEADER_HEIGHT = 24;
const ROW_HEIGHT = 32;
const GAP = 24;
const COLUMN_MIN_WIDTH = 340;

const SettingsManagers = ({ modules, isEnterpriseEditionValid }: SettingsManagersProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [status, setStatus] = useState<ManagerStatusFilter>('all');
  const [search, setSearch] = useState('');

  const managers = toManagerItems(modules, t_i18n, isEnterpriseEditionValid);
  const counts = countManagers(managers);
  // The Enterprise Edition segment only exists while some managers wait for a license, so the segments add up to "All".
  const statusFilters = STATUS_FILTERS.filter((filter) => filter !== 'unlicensed' || counts.unlicensed > 0);
  const activeStatus = statusFilters.includes(status) ? status : 'all';
  const groups = groupManagers(filterManagers(managers, activeStatus, search), t_i18n);

  const filterLabels: Record<ManagerStatusFilter, string> = {
    all: t_i18n('All'),
    enabled: t_i18n('Enabled'),
    disabled: t_i18n('Disabled'),
    unlicensed: t_i18n('Enterprise Edition'),
  };

  const resetFilters = () => {
    setStatus('all');
    setSearch('');
  };

  const renderStatus = (manager: ManagerItem) => {
    if (manager.status === 'enabled') {
      return <ItemBoolean label={t_i18n('Enabled')} status={true} />;
    }
    if (manager.status === 'unlicensed') {
      return (
        <ItemBoolean
          neutralLabel={t_i18n('Enterprise Edition')}
          status={null}
          tooltip={t_i18n('Available with the Enterprise Edition')}
          labelTextTransform="none"
        />
      );
    }
    return <ItemBoolean label={t_i18n('Disabled')} status={false} />;
  };

  return (
    <Card title={t_i18n('Managers')} data-testid="settings-managers">
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 2 }}>
        <ToggleButtonGroup
          exclusive
          value={activeStatus}
          aria-label={t_i18n('Filter managers by status')}
          onChange={(_, value: ManagerStatusFilter | null) => {
            if (value) setStatus(value);
          }}
        >
          {statusFilters.map((filter) => (
            <ToggleButton
              key={filter}
              value={filter}
              data-testid={`settings-managers-filter-${filter}`}
              sx={{ gap: 1, paddingX: 1.5, textTransform: 'none' }}
            >
              {filterLabels[filter]}
              <Box component="span" sx={{ color: theme.palette.text.secondary }}>{counts[filter]}</Box>
            </ToggleButton>
          ))}
        </ToggleButtonGroup>
        <SearchField
          size="md"
          value={search}
          placeholder={t_i18n('Search managers')}
          aria-label={t_i18n('Search managers')}
          clearLabel={t_i18n('Clear')}
          onChange={(event) => setSearch(event.target.value)}
          onClear={() => setSearch('')}
          autoComplete="off"
          data-testid="settings-managers-search"
        />
      </Box>
      {groups.length === 0 ? (
        <Box
          data-testid="settings-managers-empty"
          sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1, paddingTop: 3 }}
        >
          <Typography variant="body2" color="textSecondary">
            {t_i18n('No manager matches these filters')}
          </Typography>
          <Button variant="tertiary" size="small" onClick={resetFilters}>
            {t_i18n('Clear filters')}
          </Button>
        </Box>
      ) : (
        <Box
          sx={{
            display: 'grid',
            gridTemplateColumns: `repeat(auto-fill, minmax(${COLUMN_MIN_WIDTH}px, 1fr))`,
            gridAutoRows: `${GRID_ROW_UNIT}px`,
            gridAutoFlow: 'row dense',
            columnGap: `${GAP}px`,
            paddingTop: `${GAP}px`,
            // Every group carries the gap below it; the last one of each column must not add it to the card.
            marginBottom: `-${GAP}px`,
          }}
        >
          {groups.map((group) => (
            <Box
              key={group.domain}
              component="section"
              aria-labelledby={`settings-managers-group-${group.domain}`}
              data-testid={`settings-managers-group-${group.domain}`}
              sx={{
                // Masonry packing: each group spans exactly its own height, so the dense flow fills the shortest column.
                gridRowEnd: `span ${(HEADER_HEIGHT + group.managers.length * ROW_HEIGHT + GAP) / GRID_ROW_UNIT}`,
                paddingBottom: `${GAP}px`,
              }}
            >
              <SettingsOverline
                id={`settings-managers-group-${group.domain}`}
                count={group.managers.length}
                adornment={group.domain === 'enterprise' ? <EEChip size="sm" /> : undefined}
              >
                {group.label}
              </SettingsOverline>
              <Box component="ul" sx={{ listStyle: 'none', margin: 0, padding: 0 }}>
                {group.managers.map((manager) => (
                  <Box
                    component="li"
                    key={manager.id}
                    data-testid={`settings-manager-${manager.id}`}
                    data-status={manager.status}
                    sx={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: 1,
                      height: ROW_HEIGHT,
                      borderBottom: `1px solid ${theme.palette.divider}`,
                    }}
                  >
                    <Typography
                      variant="body2"
                      title={manager.label}
                      sx={{ minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                    >
                      {manager.label}
                    </Typography>
                    {renderStatus(manager)}
                  </Box>
                ))}
              </Box>
            </Box>
          ))}
        </Box>
      )}
    </Card>
  );
};

export default SettingsManagers;
