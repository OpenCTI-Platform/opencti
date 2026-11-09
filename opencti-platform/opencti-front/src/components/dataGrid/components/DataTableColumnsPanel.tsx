import React, { useMemo, useState } from 'react';
import Popover from '@mui/material/Popover';
import Box from '@mui/material/Box';
import { alpha, useTheme } from '@mui/material/styles';
import { ArrowBackOutlined, DragIndicatorOutlined, RestartAltOutlined } from '@mui/icons-material';
import { DragDropContext, Draggable, Droppable, DropResult } from '@hello-pangea/dnd';
import { Checkbox, SearchField, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import type { Theme } from '../../Theme';
import { useDataTableContext } from './DataTableContext';
import { isDataColumn } from '../dataTableColumnsConfig';
import { useFormatter } from '../../i18n';

type ColumnSelection = { id: string; visible: boolean };

interface DataTableColumnsPanelProps {
  anchorEl: HTMLElement | null;
  onClose: () => void;
}

const SectionTitle = ({ title, hint }: { title: string; hint?: string }) => {
  const theme = useTheme<Theme>();
  return (
    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingX: 2, paddingTop: 1.5, paddingBottom: 0.5 }}>
      <Text variant="content-caption" style={{ fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.5, color: theme.palette.text.secondary }}>
        {title}
      </Text>
      {hint && <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>{hint}</Text>}
    </Box>
  );
};

const ellipsis = { overflow: 'hidden', whiteSpace: 'nowrap', textOverflow: 'ellipsis' } as const;

const ColumnRow = ({
  label,
  typeLabel,
  checked,
  locked = false,
  dragHandle,
  onToggle,
}: {
  label: string;
  typeLabel?: string;
  checked: boolean;
  locked?: boolean;
  dragHandle?: React.ReactNode;
  onToggle: () => void;
}) => {
  const theme = useTheme<Theme>();
  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 1,
        height: 34,
        paddingRight: 2,
        paddingLeft: dragHandle ? 1 : 2,
        // Same visual language as the submenu it replaces: a displayed column is highlighted, with a left border.
        borderLeft: `3px solid ${checked ? theme.palette.primary.main : 'transparent'}`,
        backgroundColor: checked ? alpha(theme.palette.primary.main ?? '#000000', 0.12) : 'transparent',
      }}
    >
      {dragHandle}
      <Checkbox
        aria-label={label}
        checked={checked}
        disabled={locked}
        onCheckedChange={onToggle}
      />
      <Text variant="content-compact" as="span" style={{ ...ellipsis, flex: 1, opacity: checked ? 1 : 0.7 }}>
        {label}
      </Text>
      {typeLabel && (
        <Text variant="content-caption" style={{ ...ellipsis, color: theme.palette.text.secondary }}>
          {typeLabel}
        </Text>
      )}
    </Box>
  );
};

/**
 * "Manage columns" panel of the table settings: show, hide and reorder the displayed columns,
 * add attributes of the listed entities, and go back to the default view.
 * An added attribute joins the displayed columns right away, so that it can be moved before applying.
 * Changes are only applied to the list with "Apply", so the data is fetched again at most once.
 */
const DataTableColumnsPanel = ({ anchorEl, onClose }: DataTableColumnsPanelProps) => {
  const theme = useTheme<Theme>();
  const {
    columns,
    columnsCatalog,
    defaultColumnIds,
    lockedColumnId,
    applyColumnsSelection,
    resetColumns,
    columnsScopeLabel,
  } = useDataTableContext();
  const { t_i18n } = useFormatter();

  const [displayed, setDisplayed] = useState<ColumnSelection[]>(
    () => columns.filter(isDataColumn).map(({ id, visible }) => ({ id, visible: visible ?? true })),
  );
  const [search, setSearch] = useState('');

  const getLabel = (id: string) => t_i18n(columnsCatalog[id]?.label ?? id);
  const getTypeLabel = (id: string) => {
    const typeLabel = columnsCatalog[id]?.typeLabel;
    return typeLabel ? t_i18n(typeLabel) : undefined;
  };
  const matchSearch = (id: string) => getLabel(id).toLowerCase().includes(search.trim().toLowerCase());

  const availableIds = useMemo(() => Object.keys(columnsCatalog)
    .filter((id) => !displayed.some((c) => c.id === id))
    .sort((a, b) => getLabel(a).localeCompare(getLabel(b))), [columnsCatalog, displayed]);

  const isSearching = search.trim().length > 0;
  const shownDisplayed = displayed.filter(({ id }) => matchSearch(id));
  const shownAvailable = availableIds.filter(matchSearch);
  const visibleCount = displayed.filter(({ visible }) => visible).length;

  const toggleDisplayed = (id: string) => {
    setDisplayed((current) => {
      const column = current.find((c) => c.id === id);
      // An added attribute that is unchecked goes back to the attributes that can be added,
      // a default column stays in place, greyed, so that it can be shown again.
      if (column?.visible && !defaultColumnIds.includes(id)) {
        return current.filter((c) => c.id !== id);
      }
      return current.map((c) => (c.id === id ? { ...c, visible: !c.visible } : c));
    });
  };
  // An added attribute is appended at the end of the displayed columns.
  const addAttribute = (id: string) => {
    setDisplayed((current) => [...current, { id, visible: true }]);
  };
  const onDragEnd = ({ source, destination }: DropResult) => {
    if (!destination) return;
    setDisplayed((current) => {
      const reordered = [...current];
      const [moved] = reordered.splice(source.index, 1);
      reordered.splice(destination.index, 0, moved);
      return reordered;
    });
  };

  const apply = () => {
    // A hidden attribute that is not a default column goes back to the attributes that can be added.
    applyColumnsSelection(displayed.filter(({ id, visible }) => visible || defaultColumnIds.includes(id)));
    onClose();
  };
  const reset = () => {
    resetColumns();
    onClose();
  };

  return (
    <Popover
      open={!!anchorEl}
      anchorEl={anchorEl}
      onClose={onClose}
      anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      transformOrigin={{ vertical: 'top', horizontal: 'right' }}
      slotProps={{ paper: { sx: { width: 340, marginTop: 0.5, display: 'flex', flexDirection: 'column', maxHeight: '75vh' } } }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, paddingX: 1, paddingTop: 1 }}>
        <IconButton size="small" aria-label={t_i18n('Back')} onClick={onClose}>
          <ArrowBackOutlined fontSize="small" />
        </IconButton>
        <Text variant="title-xs" as="h2" style={{ flex: 1, margin: 0 }}>{t_i18n('Columns')}</Text>
        <Text variant="content-caption" style={{ paddingRight: 8, color: theme.palette.text.secondary }}>
          {[columnsScopeLabel, t_i18n('only for you')].filter(Boolean).join(' · ')}
        </Text>
      </Box>
      <Box sx={{ paddingX: 2, paddingY: 1 }}>
        <SearchField
          size="sm"
          value={search}
          placeholder={t_i18n('Search attributes...')}
          aria-label={t_i18n('Search attributes...')}
          clearLabel={t_i18n('Clear')}
          onChange={(event) => setSearch(event.target.value)}
          onClear={() => setSearch('')}
          autoComplete="off"
        />
      </Box>
      <Box sx={{ overflowY: 'auto', flex: 1 }}>
        <SectionTitle
          title={`${t_i18n('Displayed')} · ${t_i18n('{count} of {total}', { values: { count: visibleCount, total: displayed.length } })}`}
          hint={isSearching ? undefined : t_i18n('Drag to reorder')}
        />
        <DragDropContext onDragEnd={onDragEnd}>
          <Droppable droppableId="displayed-columns">
            {(provided) => (
              <div ref={provided.innerRef} {...provided.droppableProps}>
                {displayed.map(({ id, visible }, index) => (
                  <Draggable key={id} draggableId={id} index={index} isDragDisabled={isSearching}>
                    {(item) => (
                      <div
                        ref={item.innerRef}
                        {...item.draggableProps}
                        style={{ ...item.draggableProps.style, display: shownDisplayed.some((c) => c.id === id) ? undefined : 'none' }}
                      >
                        <ColumnRow
                          label={getLabel(id)}
                          typeLabel={getTypeLabel(id)}
                          checked={visible}
                          locked={id === lockedColumnId}
                          onToggle={() => toggleDisplayed(id)}
                          dragHandle={(
                            <Box
                              {...item.dragHandleProps}
                              aria-label={t_i18n('Drag to reorder')}
                              sx={{ display: 'flex', cursor: isSearching ? 'default' : 'grab', color: theme.palette.text.secondary }}
                            >
                              <DragIndicatorOutlined fontSize="small" />
                            </Box>
                          )}
                        />
                      </div>
                    )}
                  </Draggable>
                ))}
                {provided.placeholder}
              </div>
            )}
          </Droppable>
        </DragDropContext>
        {availableIds.length > 0 && (
          <>
            <SectionTitle
              title={t_i18n('Add attributes')}
              hint={t_i18n('{count} available', { values: { count: availableIds.length } })}
            />
            {shownAvailable.map((id) => (
              <ColumnRow
                key={id}
                label={getLabel(id)}
                typeLabel={getTypeLabel(id)}
                checked={false}
                onToggle={() => addAttribute(id)}
              />
            ))}
          </>
        )}
        {isSearching && shownDisplayed.length === 0 && shownAvailable.length === 0 && (
          <Text variant="content-compact" style={{ padding: '8px 16px', color: theme.palette.text.secondary }}>
            {t_i18n('No attribute matches your search')}
          </Text>
        )}
      </Box>
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 1,
          padding: 1.5,
          borderTop: `1px solid ${theme.palette.divider}`,
        }}
      >
        <Button variant="tertiary" size="small" startIcon={<RestartAltOutlined fontSize="small" />} onClick={reset}>
          {t_i18n('Reset to default')}
        </Button>
        <Box sx={{ flex: 1 }} />
        <Button variant="secondary" size="small" onClick={onClose}>
          {t_i18n('Cancel')}
        </Button>
        <Button size="small" onClick={apply}>
          {t_i18n('Apply')}
        </Button>
      </Box>
    </Popover>
  );
};

export default DataTableColumnsPanel;
