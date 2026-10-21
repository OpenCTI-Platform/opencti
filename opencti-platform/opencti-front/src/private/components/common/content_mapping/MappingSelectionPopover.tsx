import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Box, Popover } from '@mui/material';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { alpha, useTheme } from '@mui/material/styles';
import { fetchQuery } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import ItemEntityType from '../../../../components/ItemEntityType';
import { contentMappingSearchQuery } from './contentMappingQueries';
import { contentMappingQueriesSearchQuery$data } from './__generated__/contentMappingQueriesSearchQuery.graphql';
import { MappableEntity, mappingKey } from './contentMappingModel';
import { hashAlgorithmOf, isDefanged, refangValue, typeCandidates } from './mappingValue';
import { canCreateType } from './useContentMappingActions';
import type { TextSelection } from './ContentMappingDocument';

type ExistingMatch = MappableEntity & { containersCount: number };

type PopoverOption
  = | { kind: 'existing'; entity: ExistingMatch }
    | { kind: 'create'; type: string };

interface MappingSelectionPopoverProps {
  selection: TextSelection | null;
  onClose: () => void;
  onMapExisting: (value: string, entity: MappableEntity) => void;
  onCreate: (value: string, type: string) => void;
}

const MAX_CREATE_OPTIONS = 4;

type SearchNode = NonNullable<NonNullable<NonNullable<contentMappingQueriesSearchQuery$data['stixCoreObjects']>['edges']>[number]>['node'];

// The search is fuzzy: only the objects whose name, alias or id is the value (or contains it) are offered.
const matchesValue = (node: SearchNode, value: string) => {
  const target = mappingKey(value);
  const names = [node.representative?.main, ...(node.aliases ?? []), ...(node.x_opencti_aliases ?? []), node.x_mitre_id]
    .filter((name): name is string => !!name)
    .map(mappingKey);
  return names.some((name) => name === target || name.includes(target) || (name.length > 2 && target.includes(name)));
};

// The search also matches the text of containers (the report itself contains the value): only objects
// the value can be mapped to are offered.
const CONTAINER_TYPES = ['Report', 'Grouping', 'Note', 'Opinion', 'Observed-Data', 'Case-Incident', 'Case-Rfi', 'Case-Rft', 'Task', 'Feedback'];
const NOT_CONTAINER_FILTERS = {
  mode: 'and',
  filterGroups: [],
  filters: [{ key: ['entity_type'], values: CONTAINER_TYPES, operator: 'not_eq', mode: 'and' }],
};

// Where the value goes when the object is created (US.3): shown so that nothing has to be copied by hand.
const fieldHint = (type: string, value: string, t_i18n: (s: string) => string) => {
  const algorithm = type === 'StixFile' ? hashAlgorithmOf(value) : null;
  if (algorithm) return { field: `hashes.${algorithm}`, detail: `${t_i18n('detected')} (${value.length} ${t_i18n('chars')})` };
  if (type === 'StixFile' || !type.includes('-') || ['Intrusion-Set', 'Threat-Actor-Group', 'Attack-Pattern'].includes(type)) {
    return { field: `name = ${value}`, detail: null };
  }
  return { field: value, detail: null };
};

const MappingSelectionPopover = ({ selection, onClose, onMapExisting, onCreate }: MappingSelectionPopoverProps) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const [existing, setExisting] = useState<ExistingMatch[] | null>(null);
  const [showAllTypes, setShowAllTypes] = useState(false);
  const [active, setActive] = useState(0);
  const listRef = useRef<HTMLDivElement>(null);

  const raw = selection?.text ?? '';
  const value = refangValue(raw);
  const candidates = useMemo(() => typeCandidates(raw), [raw]);
  const compatible = candidates.filter((c) => c.compatible && canCreateType(c.type));
  const incompatible = candidates.filter((c) => !c.compatible).slice(0, 2);
  const createOptions = showAllTypes ? compatible : compatible.slice(0, MAX_CREATE_OPTIONS);

  useEffect(() => {
    if (!selection) return;
    setExisting(null);
    setActive(0);
    setShowAllTypes(false);
    fetchQuery(contentMappingSearchQuery, { search: value, filters: NOT_CONTAINER_FILTERS })
      .toPromise()
      .then((data) => {
        const nodes = ((data as contentMappingQueriesSearchQuery$data)?.stixCoreObjects?.edges ?? [])
          .flatMap((edge) => (edge?.node && matchesValue(edge.node, value) ? [{ ...edge.node, containersCount: edge.node.containersNumber?.total ?? 0 }] : []));
        // Exact name or value matches first: they are the ones to reuse rather than duplicate.
        const exact = (entity: ExistingMatch) => mappingKey(entity.representative?.main ?? '') === mappingKey(value);
        setExisting([...nodes.filter(exact), ...nodes.filter((n) => !exact(n))].slice(0, 4));
      });
  }, [selection]);

  useEffect(() => {
    if (selection) listRef.current?.focus();
  }, [selection, existing]);

  const options: PopoverOption[] = [
    ...(existing ?? []).map((entity) => ({ kind: 'existing' as const, entity })),
    ...createOptions.map(({ type }) => ({ kind: 'create' as const, type })),
  ];

  const choose = (option: PopoverOption | undefined) => {
    if (!option) return;
    if (option.kind === 'existing') onMapExisting(raw, option.entity);
    else onCreate(raw, option.type);
    onClose();
  };

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === 'ArrowDown') setActive((i) => Math.min(i + 1, options.length - 1));
    else if (event.key === 'ArrowUp') setActive((i) => Math.max(i - 1, 0));
    else if (event.key === 'Enter') choose(options[active]);
    else if (/^[1-9]$/.test(event.key)) choose(options.filter((o) => o.kind === 'create')[Number(event.key) - 1]);
    else return;
    event.preventDefault();
  };

  const sectionTitle = (label: string) => (
    <Box sx={{ fontSize: 10, fontWeight: 600, letterSpacing: 0.4, textTransform: 'uppercase', color: theme.palette.text.disabled, padding: '6px 10px 2px' }}>
      {label}
    </Box>
  );
  const optionSx = (index: number) => ({
    display: 'flex',
    alignItems: 'center',
    gap: 1,
    padding: '6px 10px',
    borderRadius: '4px',
    cursor: 'pointer',
    backgroundColor: index === active ? alpha(theme.palette.primary.main, 0.14) : 'transparent',
  });
  const shortcut = (label: string) => (
    <Box component="span" sx={{ marginLeft: 'auto', fontSize: 10, fontFamily: 'monospace', padding: '0 5px', borderRadius: '3px', border: `1px solid ${theme.palette.divider}`, color: theme.palette.text.secondary }}>
      {label}
    </Box>
  );
  const createdIndex = (existing ?? []).length;

  return (
    <Popover
      open={!!selection}
      onClose={onClose}
      anchorReference="anchorPosition"
      anchorPosition={selection ? { top: selection.rect.bottom + 6, left: selection.rect.left } : undefined}
      slotProps={{ paper: { sx: { width: 460, padding: 1, border: `1px solid ${alpha(theme.palette.primary.main, 0.7)}` } } }}
      disableRestoreFocus
    >
      <Box ref={listRef} tabIndex={-1} onKeyDown={handleKeyDown} role="listbox" aria-label={t_i18n('Map the selection')} sx={{ outline: 'none', fontSize: 13 }}>
        {isDefanged(raw) && (
          <Box sx={{ display: 'flex', gap: 1, padding: '2px 10px 6px', fontFamily: 'monospace', fontSize: 12 }}>
            <span style={{ color: theme.palette.text.secondary }}>{raw}</span>
            <span style={{ color: theme.palette.text.disabled }}>→</span>
            <span style={{ color: theme.palette.success.main, fontWeight: 600 }}>{value}</span>
          </Box>
        )}
        {existing === null && sectionTitle(t_i18n('Searching the platform…'))}
        {existing && existing.length > 0 && sectionTitle(t_i18n('Already in the platform'))}
        {existing?.map((entity, index) => (
          <Box key={entity.id} role="option" aria-selected={index === active} sx={optionSx(index)} onMouseEnter={() => setActive(index)} onClick={() => choose(options[index])}>
            <span style={{ color: theme.palette.success.main, fontWeight: 600 }}>↗</span>
            <ItemEntityType entityType={entity.entity_type} />
            <span style={{ fontWeight: 500 }}>{entity.representative?.main}</span>
            {entity.containersCount > 0 && (
              <span style={{ fontSize: 11, color: theme.palette.text.secondary }}>· {t_i18n('seen in')} {entity.containersCount} {t_i18n('containers')}</span>
            )}
            {index === active && shortcut('↵')}
          </Box>
        ))}
        {sectionTitle(t_i18n('Create and map'))}
        {createOptions.map(({ type }, index) => {
          const hint = fieldHint(type, value, t_i18n);
          const optionIndex = createdIndex + index;
          return (
            <Box key={type} role="option" aria-selected={optionIndex === active} sx={optionSx(optionIndex)} onMouseEnter={() => setActive(optionIndex)} onClick={() => choose(options[optionIndex])}>
              <span style={{ color: theme.palette.primary.main, fontWeight: 600 }}>+</span>
              <ItemEntityType entityType={type} />
              <span style={{ fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{hint.field}</span>
              {hint.detail && <span style={{ fontSize: 11, color: theme.palette.text.secondary, whiteSpace: 'nowrap' }}>{hint.detail}</span>}
              {shortcut(optionIndex === active ? '↵' : String(index + 1))}
            </Box>
          );
        })}
        {incompatible.map(({ type, reason }) => (
          <Tooltip key={type}>
            <TooltipTrigger asChild>
              <Box tabIndex={0} sx={{ display: 'flex', alignItems: 'center', gap: 1, padding: '6px 10px', opacity: 0.45, cursor: 'not-allowed' }}>
                <span>+</span>
                <ItemEntityType entityType={type} />
                <span>{t_i18n('Not valid for this value')}</span>
              </Box>
            </TooltipTrigger>
            <TooltipContent side="left">{t_i18n(reason ?? '')}</TooltipContent>
          </Tooltip>
        ))}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, padding: '8px 10px 2px', fontSize: 12 }}>
          {compatible.length > MAX_CREATE_OPTIONS && !showAllTypes && (
            <Box component="button" type="button" onClick={() => setShowAllTypes(true)} sx={{ all: 'unset', cursor: 'pointer', color: theme.palette.primary.main, fontWeight: 500 }}>
              {t_i18n('Other type…')}
            </Box>
          )}
          <Box component="button" type="button" onClick={onClose} sx={{ all: 'unset', cursor: 'pointer', color: theme.palette.text.secondary }}>
            {t_i18n('Ignore')}
          </Box>
          <Box sx={{ marginLeft: 'auto', fontSize: 10, color: theme.palette.text.disabled }}>{t_i18n('↑↓ navigate · ↵ validate · Esc')}</Box>
        </Box>
      </Box>
    </Popover>
  );
};

export default MappingSelectionPopover;
