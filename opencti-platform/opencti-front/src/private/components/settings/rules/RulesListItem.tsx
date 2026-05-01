import React, { CSSProperties, useEffect, useMemo, useState } from 'react';
import { Grid2 as Grid, Stack } from '@mui/material';
import Box from '@mui/material/Box';
import DangerZoneBlock from '@components/common/danger_zone/DangerZoneBlock';
import FormGroup from '@mui/material/FormGroup';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import {
  AddOutlined,
  ArrowRightAlt,
  DeleteOutline,
  ExpandMore,
} from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import Typography from '@mui/material/Typography';
import TextField from '@mui/material/TextField';
import Tooltip from '@mui/material/Tooltip';
import Chip from '@mui/material/Chip';
import IconButton from '@mui/material/IconButton';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import Filters from '@components/common/lists/Filters';
import FilterIconButton from '../../../../components/FilterIconButton';
import { useFormatter } from '../../../../components/i18n';
import { Rule, Task } from './RulesList';
import useAuth from '../../../../utils/hooks/useAuth';
import RuleListItemProgressBar from './RulesListItemProgressBar';
import type { Theme } from '../../../../components/Theme';
import { RuleTag } from './RulesListItemTag';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { Filter, FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { removeIdAndIncorrectKeysFromFilterGroupObject, useAvailableFilterKeysForEntityTypes } from '../../../../utils/filters/filtersUtils';
import { resolveTypesForRelationship } from '../../../../utils/Relation';
interface ConfiguredRule {
  id: string;
  name: string;
  description: string;
  active: boolean;
  expanded: boolean;
}

interface RuleEntity {
  key: string;
  label: string;
  /** Display label used as entityType fallback (from rule display, e.g. "Entity A") */
  entityType: string;
  /** Concrete OpenCTI entity types valid for this slot, resolved from schema. Used for filter builder. */
  resolvedEntityTypes: string[];
  initialFilters: FilterGroup;
}

interface RuleTriplet {
  key: string;
  sourceKey: string;
  targetKey: string;
  relationLabel: string;
  relationType: string;
  relationResolvedTypes: string[];
}

const createId = () => `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;

const createRevokedFalseFilterGroup = (): FilterGroup => ({
  mode: 'and',
  filters: [{
    key: 'revoked',
    values: ['false'],
    operator: 'eq',
    mode: 'or',
  }],
  filterGroups: [],
});

const cloneFilterGroup = (filterGroup: FilterGroup): FilterGroup => ({
  mode: filterGroup.mode,
  filters: filterGroup.filters.map((filter) => ({
    ...filter,
    values: [...filter.values],
  })),
  filterGroups: filterGroup.filterGroups.map(cloneFilterGroup),
});

// Parse display labels like "Indicator A" → { type: "Indicator", identifier: "A" }
const parseDisplayLabel = (label: string | null | undefined): { type: string; identifier: string | undefined } => {
  if (!label) return { type: '', identifier: undefined };
  const trimmed = label.trim();
  const lastSpaceIdx = trimmed.lastIndexOf(' ');
  if (lastSpaceIdx === -1) return { type: trimmed, identifier: undefined };
  const lastPart = trimmed.slice(lastSpaceIdx + 1);
  if (/^[A-Z]$/.test(lastPart)) {
    return { type: trimmed.slice(0, lastSpaceIdx), identifier: lastPart };
  }
  return { type: trimmed, identifier: undefined };
};

const buildRuleEntities = (
  rule: NonNullable<Rule>,
  schemaRelationsTypesMapping: Map<string, readonly string[]>,
): RuleEntity[] => {
  const ifSteps = rule.display?.if ?? [];
  const entities: RuleEntity[] = [];
  const seen = new Set<string>();
  const isRaiseIncidentBasedOnSighting = rule.name === 'Raise incident based on sighting';

  const addEntity = (
    entityType: string | null | undefined,
    identifier: string | null | undefined,
    relationshipType: string | null | undefined,
    direction: 'from' | 'to',
    withRevokedFalse = false,
  ) => {
    if (!entityType || entityType.trim().length === 0) return;

    const normalized = entityType.trim();
    const normId = identifier?.trim();
    const label = normId ? `${normalized} ${normId}` : normalized;
    const key = `${normalized}::${normId ?? ''}`;
    if (seen.has(key)) return;
    seen.add(key);

    // Resolve concrete entity types from schema for this relationship slot
    let resolvedEntityTypes: string[] = [];
    const relType = relationshipType?.trim().toLowerCase();
    if (relType && schemaRelationsTypesMapping.size > 0) {
      resolvedEntityTypes = resolveTypesForRelationship(
        schemaRelationsTypesMapping,
        relType,
        direction,
      );
    }
    // Fall back to generic if schema resolution yielded nothing
    if (resolvedEntityTypes.length === 0) {
      resolvedEntityTypes = ['Stix-Core-Object'];
    }

    entities.push({
      key,
      label,
      entityType: normalized,
      resolvedEntityTypes,
      initialFilters: withRevokedFalse ? createRevokedFalseFilterGroup() : createEmptyFilterGroup(),
    });
  };

  ifSteps.forEach((step) => {
    const { type: sourceType, identifier: sourceIdentifier } = parseDisplayLabel(step?.source);
    const relType = step?.relation;
    // 'relationship_has' represents a property check on the source entity, not a real
    // relationship to another entity — skip adding target as an entity slot
    const isPropertyStep = relType === 'relationship_has';

    const shouldPresetRevoked = isRaiseIncidentBasedOnSighting
      && sourceType.toLowerCase() === 'indicator'
      && sourceIdentifier?.toUpperCase() === 'A';

    addEntity(sourceType, sourceIdentifier, isPropertyStep ? undefined : relType, 'from', shouldPresetRevoked);
    if (!isPropertyStep) {
      const { type: targetType, identifier: targetIdentifier } = parseDisplayLabel(step?.target);
      addEntity(targetType, targetIdentifier, relType, 'to', false);
    }
  });

  return entities.length > 0
    ? entities
    : [{
      key: 'Stix-Core-Object::',
      label: 'Stix-Core-Object',
      entityType: 'Stix-Core-Object',
      resolvedEntityTypes: ['Stix-Core-Object'],
      initialFilters: createEmptyFilterGroup(),
    }];
};

const buildRuleTriplets = (
  rule: NonNullable<Rule>,
): RuleTriplet[] => {
  const ifSteps = rule.display?.if ?? [];
  return ifSteps
    .filter((step) => step?.relation && step.relation !== 'relationship_has')
    .map((step, index) => {
      const { type: sourceType, identifier: sourceIdentifier } = parseDisplayLabel(step?.source);
      const { type: targetType, identifier: targetIdentifier } = parseDisplayLabel(step?.target);
      const relationType = (step?.relation ?? '').replace(/^relationship_/, '').trim();
      const relationResolvedTypes = relationType
        ? [relationType, 'stix-core-relationship']
        : ['stix-core-relationship'];
      return {
        key: `triplet-${index}`,
        sourceKey: `${sourceType}::${sourceIdentifier ?? ''}`,
        targetKey: `${targetType}::${targetIdentifier ?? ''}`,
        relationLabel: step?.relation ?? '',
        relationType: relationType || 'Stix-Core-Relationship',
        relationResolvedTypes,
      };
    });
};

const createEmptyFilterGroup = (): FilterGroup => ({
  mode: 'and',
  filters: [],
  filterGroups: [],
});

interface ConfiguredRuleEntityFiltersProps {
  entityLabel: string;
  entityType: string;
  resolvedEntityTypes: string[];
  fallbackEntityTypes?: string[];
  hideEntityTypeFilter?: boolean;
  blockedFilterKeys?: string[];
  initialFilters: FilterGroup;
  disabled: boolean;
  onFiltersChange: (filters: FilterGroup) => void;
}

const ConfiguredRuleEntityFilters = ({
  entityLabel,
  entityType,
  resolvedEntityTypes,
  fallbackEntityTypes = ['Stix-Core-Object'],
  hideEntityTypeFilter = false,
  blockedFilterKeys = [],
  initialFilters,
  disabled,
  onFiltersChange,
}: ConfiguredRuleEntityFiltersProps) => {
  const fallbackFilterKeys = useAvailableFilterKeysForEntityTypes(fallbackEntityTypes);
  const resolvedFilterKeys = useAvailableFilterKeysForEntityTypes(resolvedEntityTypes);
  const rawAvailableFilterKeys = resolvedFilterKeys.length > 0 ? resolvedFilterKeys : fallbackFilterKeys;
  const availableFilterKeys = useMemo(() => {
    const blockedKeys = new Set(
      ['regardingOf', 'dynamicRegardingOf', ...blockedFilterKeys].map((k) => k.toLowerCase()),
    );
    if (hideEntityTypeFilter) {
      blockedKeys.add('entity_type');
      blockedKeys.add('relationship_type');
      blockedKeys.add('fromTypes');
      blockedKeys.add('toTypes');
    }
    return rawAvailableFilterKeys.filter((key) => !blockedKeys.has(key.toLowerCase()));
  }, [rawAvailableFilterKeys, hideEntityTypeFilter, blockedFilterKeys]);
  const searchEntityTypes = resolvedEntityTypes.length > 0 ? resolvedEntityTypes : fallbackEntityTypes;

  const initialFilterState = useMemo(() => {
    const sanitized = removeIdAndIncorrectKeysFromFilterGroupObject(
      cloneFilterGroup(initialFilters),
      availableFilterKeys,
    );
    return sanitized ?? createEmptyFilterGroup();
  }, [initialFilters, availableFilterKeys]);
  const [filters, filterHelpers] = useFiltersState(initialFilterState);

  // Notify parent when filter state changes
  const isFirstRender = React.useRef(true);
  useEffect(() => {
    const sanitizedFilters = removeIdAndIncorrectKeysFromFilterGroupObject(filters, availableFilterKeys)
      ?? createEmptyFilterGroup();
    if (isFirstRender.current) {
      isFirstRender.current = false;
      // Still call on mount so parent's map is initialised with preset filters
      onFiltersChange(sanitizedFilters);
      return;
    }
    onFiltersChange(sanitizedFilters);
  }, [filters, availableFilterKeys]);

  return (
    <Stack
      spacing={1}
      sx={{
        border: (theme) => `1px solid ${theme.palette.divider}`,
        borderRadius: 1,
        p: 2,
      }}
    >
      <Typography variant="body2" fontWeight={600}>
        {entityLabel}
      </Typography>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <Filters
          availableFilterKeys={availableFilterKeys}
          helpers={filterHelpers}
          searchContext={{ entityTypes: searchEntityTypes }}
          disabled={disabled}
        />
        <FilterIconButton
          availableFilterKeys={availableFilterKeys}
          filters={filters}
          helpers={filterHelpers}
          redirection
          searchContext={{ entityTypes: searchEntityTypes }}
        />
      </div>
    </Stack>
  );
};

// ─── Compact filter chip summary for the preview ────────────────────────────

const formatFilterValue = (v: string): string => {
  if (v === 'true') return 'true';
  if (v === 'false') return 'false';
  return v.length > 20 ? `${v.slice(0, 18)}…` : v;
};

const operatorLabel = (op?: string) => {
  switch (op) {
    case 'not_eq': return '≠';
    case 'gt': return '>';
    case 'gte': return '≥';
    case 'lt': return '<';
    case 'lte': return '≤';
    case 'nil': return 'is empty';
    case 'not_nil': return 'is not empty';
    default: return '=';
  }
};

const FilterSummaryChips = ({ filters }: { filters: FilterGroup }) => {
  const theme = useTheme<Theme>();
  const activeFilters: Filter[] = filters.filters ?? [];
  if (activeFilters.length === 0) return null;
  return (
    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
      {activeFilters.map((f) => {
        const op = operatorLabel(f.operator);
        const vals = f.values?.slice(0, 2).map(formatFilterValue).join(', ');
        const extra = (f.values?.length ?? 0) > 2 ? ` +${(f.values?.length ?? 0) - 2}` : '';
        const label = ['nil', 'not_nil'].includes(f.operator ?? '')
          ? `${f.key} ${op}`
          : `${f.key} ${op} ${vals}${extra}`;
        return (
          <Chip
            key={f.id ?? f.key}
            label={label}
            size="small"
            variant="outlined"
            sx={{ fontSize: '0.65rem', height: 20, color: theme.palette.text.secondary }}
          />
        );
      })}
    </Box>
  );
};

// ─── Rule preview inside the accordion summary ──────────────────────────────

interface ConfiguredRulePreviewProps {
  rule: NonNullable<Rule>;
  filtersMap: Record<string, FilterGroup>;
}

const ConfiguredRulePreview = ({ rule, filtersMap }: ConfiguredRulePreviewProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const getFilters = (rawLabel?: string | null): FilterGroup | undefined => {
    if (!rawLabel) return undefined;
    const { type, identifier } = parseDisplayLabel(rawLabel);
    if (!type) return undefined;
    const key = `${type}::${identifier ?? ''}`;
    return filtersMap[key];
  };

  const hasAnyFilters = Object.values(filtersMap).some((fg) => (fg?.filters?.length ?? 0) > 0);
  if (!hasAnyFilters) return null;

  const styleStepPrimaryRow: CSSProperties = {
    display: 'grid',
    gridTemplateColumns: '96px minmax(0, 1fr) minmax(0, 1fr) minmax(0, 1fr)',
    alignItems: 'center',
    columnGap: theme.spacing(1),
    padding: `${theme.spacing(0.5)} ${theme.spacing(0.5)} 0`,
    width: '100%',
    minHeight: 28,
  };

  const styleStepConditionsRow: CSSProperties = {
    display: 'grid',
    gridTemplateColumns: '96px minmax(0, 1fr) minmax(0, 1fr) minmax(0, 1fr)',
    alignItems: 'flex-start',
    columnGap: theme.spacing(1),
    padding: `0 ${theme.spacing(0.5)} ${theme.spacing(0.5)}`,
    width: '100%',
  };

  const stylePreviewBlock: CSSProperties = {
    flex: 1,
    border: `1px solid ${theme.palette.divider}`,
    borderRadius: Number(theme.shape.borderRadius),
    padding: theme.spacing(1),
    display: 'flex',
    flexDirection: 'column',
    gap: theme.spacing(0.5),
    minWidth: 420,
  };

  return (
    <Box
      sx={{
        mt: 1,
        pt: 1,
        borderTop: (t) => `1px solid ${t.palette.divider}`,
        width: '100%',
      }}
      onClick={(e) => e.stopPropagation()}
    >
      <Box sx={{ display: 'flex', alignItems: 'stretch', gap: 2, flexWrap: 'wrap' }}>
        {/* IF block */}
        <Box style={stylePreviewBlock}>
          {(rule.display?.if ?? []).map((step, index) => (
            <Box key={index}>
              <Box sx={styleStepPrimaryRow}>
                <Box sx={{ minWidth: 0 }}>
                  <Typography variant="caption" color="text.secondary" sx={{ textAlign: 'left' }}>
                    {t_i18n('IF')}
                  </Typography>
                </Box>
                <Box sx={{ minWidth: 0, display: 'flex', justifyContent: 'center' }}>
                  <RuleTag color={step?.source_color} label={step?.source ?? undefined} />
                </Box>
                <Box sx={{ minWidth: 0, display: 'flex', justifyContent: 'center' }}>
                  {step?.relation && (
                    <Typography variant="caption" color="text.secondary" sx={{ textAlign: 'center' }}>
                      {t_i18n(step.relation)}
                    </Typography>
                  )}
                </Box>
                <Box sx={{ minWidth: 0, display: 'flex', justifyContent: 'center' }}>
                  {step?.target && step?.relation !== 'relationship_has' && (
                    <RuleTag color={step.target_color} label={step.target} />
                  )}
                </Box>
              </Box>

              <Box sx={styleStepConditionsRow}>
                <Box sx={{ minWidth: 0 }} />
                <Box sx={{ minWidth: 0 }}>
                  <FilterSummaryChips filters={getFilters(step?.source) ?? createEmptyFilterGroup()} />
                </Box>
                <Box sx={{ minWidth: 0 }}>
                  <FilterSummaryChips filters={filtersMap[`relationship::triplet-${index}`] ?? createEmptyFilterGroup()} />
                </Box>
                <Box sx={{ minWidth: 0 }}>
                  {step?.target && step?.relation !== 'relationship_has' && (
                    <FilterSummaryChips filters={getFilters(step.target) ?? createEmptyFilterGroup()} />
                  )}
                </Box>
              </Box>
            </Box>
          ))}
        </Box>

        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <ArrowRightAlt />
          <Typography variant="caption" color="text.secondary">{t_i18n('THEN')}</Typography>
        </Box>

        {/* THEN block */}
        <Box style={stylePreviewBlock}>
          {(rule.display?.then ?? []).map((step, index) => (
            <Box key={index} sx={styleStepPrimaryRow}>
              <Box sx={{ minWidth: 0, display: 'flex', justifyContent: 'flex-start' }}>
                <RuleTag action label={step?.action} />
              </Box>
              <Box sx={{ minWidth: 0, display: 'flex', justifyContent: 'center' }}>
                {step?.source && <RuleTag color={step.source_color} label={step.source} />}
              </Box>
              <Box sx={{ minWidth: 0, display: 'flex', justifyContent: 'center' }}>
                {step?.relation && (
                  <Typography variant="caption" color="text.secondary" sx={{ textAlign: 'center' }}>
                    {t_i18n(step.relation)}
                  </Typography>
                )}
              </Box>
              <Box sx={{ minWidth: 0, display: 'flex', justifyContent: 'center' }}>
                {step?.target && <RuleTag color={step.target_color} label={step.target} />}
              </Box>
            </Box>
          ))}
        </Box>
      </Box>
    </Box>
  );
};

// ─── Single configured rule accordion ───────────────────────────────────────

interface ConfiguredRuleAccordionProps {
  configuredRule: ConfiguredRule;
  rule: NonNullable<Rule>;
  ruleEntities: RuleEntity[];
  canManage: boolean;
  onChange: (id: string, data: Partial<Pick<ConfiguredRule, 'name' | 'description' | 'active'>>) => void;
  onToggleExpand: (id: string, expanded: boolean) => void;
  onDelete: (id: string) => void;
}

const ConfiguredRuleAccordion = ({
  configuredRule,
  rule,
  ruleEntities,
  canManage,
  onChange,
  onToggleExpand,
  onDelete,
}: ConfiguredRuleAccordionProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const ruleTriplets = useMemo(() => buildRuleTriplets(rule), [rule]);

  // filtersMap: entityKey → current FilterGroup (for the preview)
  const [filtersMap, setFiltersMap] = useState<Record<string, FilterGroup>>(() => {
    const initial: Record<string, FilterGroup> = {};
    ruleEntities.forEach((entity) => {
      initial[entity.key] = cloneFilterGroup(entity.initialFilters);
    });
    ruleTriplets.forEach((triplet) => {
      initial[`relationship::${triplet.key}`] = createEmptyFilterGroup();
    });
    return initial;
  });

  const entitiesByKey = useMemo(() => {
    const map = new Map<string, RuleEntity>();
    ruleEntities.forEach((entity) => map.set(entity.key, entity));
    return map;
  }, [ruleEntities]);

  const firstTripletForEntity = useMemo(() => {
    const firstByEntity = new Map<string, string>();
    ruleTriplets.forEach((triplet) => {
      if (!firstByEntity.has(triplet.sourceKey)) {
        firstByEntity.set(triplet.sourceKey, triplet.key);
      }
      if (!firstByEntity.has(triplet.targetKey)) {
        firstByEntity.set(triplet.targetKey, triplet.key);
      }
    });
    return firstByEntity;
  }, [ruleTriplets]);

  const handleEntityFiltersChange = (entityKey: string, filters: FilterGroup) => {
    setFiltersMap((prev) => ({ ...prev, [entityKey]: filters }));
  };

  return (
    <Accordion
      expanded={configuredRule.expanded}
      onChange={(_, expanded) => onToggleExpand(configuredRule.id, expanded)}
      slotProps={{ transition: { unmountOnExit: false } }}
    >
      <AccordionSummary expandIcon={<ExpandMore />}>
        <Box sx={{ display: 'flex', flexDirection: 'column', width: '100%', gap: 0.5 }}>
          {/* Row 1: name + controls */}
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              width: '100%',
              gap: theme.spacing(2),
            }}
          >
            <Typography variant="body2" fontWeight={600}>
              {configuredRule.name || t_i18n('Unnamed configuration')}
            </Typography>

            <Box sx={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
              <FormControlLabel
                onClick={(event) => event.stopPropagation()}
                onFocus={(event) => event.stopPropagation()}
                label={configuredRule.active ? t_i18n('Active') : t_i18n('Inactive')}
                control={(
                  <Switch
                    color="secondary"
                    checked={configuredRule.active}
                    onChange={(_, checked) => onChange(configuredRule.id, { active: checked })}
                    disabled={!canManage}
                  />
                )}
              />

              {canManage && (
                <Tooltip title={t_i18n('Delete')}>
                  <IconButton
                    size="small"
                    color="error"
                    onClick={(event) => {
                      event.stopPropagation();
                      onDelete(configuredRule.id);
                    }}
                  >
                    <DeleteOutline fontSize="small" />
                  </IconButton>
                </Tooltip>
              )}
            </Box>
          </Box>

          {/* Row 2: rule preview (visible when collapsed) */}
          {!configuredRule.expanded && (
            <ConfiguredRulePreview rule={rule} filtersMap={filtersMap} />
          )}
        </Box>
      </AccordionSummary>

      <AccordionDetails>
        <Stack spacing={2}>
          <TextField
            fullWidth
            label={t_i18n('Configuration name')}
            value={configuredRule.name}
            onChange={(event) => onChange(configuredRule.id, { name: event.target.value })}
            size="small"
            disabled={!canManage}
          />

          <TextField
            fullWidth
            multiline
            minRows={2}
            label={t_i18n('Configuration description')}
            value={configuredRule.description}
            onChange={(event) => onChange(configuredRule.id, { description: event.target.value })}
            size="small"
            disabled={!canManage}
          />

          <Stack spacing={1}>
            <Typography variant="body2" fontWeight={600}>
              {t_i18n('Entity filters')}
            </Typography>
            {ruleTriplets.map((triplet) => {
                const srcEntity = entitiesByKey.get(triplet.sourceKey);
                const tgtEntity = entitiesByKey.get(triplet.targetKey);
                const relationshipKey = `relationship::${triplet.key}`;
              const sourceIsEditable = firstTripletForEntity.get(triplet.sourceKey) === triplet.key;
              const targetIsEditable = firstTripletForEntity.get(triplet.targetKey) === triplet.key;
              const sourceHasFixedType = !!srcEntity && !['entity', 'observable', 'stix-core-object'].includes(srcEntity.entityType.toLowerCase());
              const targetHasFixedType = !!tgtEntity && !['entity', 'observable', 'stix-core-object'].includes(tgtEntity.entityType.toLowerCase());
                return (
                  <Box
                    key={triplet.key}
                    sx={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: 2,
                      flexWrap: 'wrap',
                    }}
                  >
                    {srcEntity && (
                      <Box sx={{ flex: '1 1 240px', minWidth: 0 }}>
                        {sourceIsEditable ? (
                          <ConfiguredRuleEntityFilters
                            entityLabel={srcEntity.label}
                            entityType={srcEntity.entityType}
                            resolvedEntityTypes={srcEntity.resolvedEntityTypes}
                            hideEntityTypeFilter={sourceHasFixedType}
                            initialFilters={srcEntity.initialFilters}
                            disabled={!canManage}
                            onFiltersChange={(filters) => handleEntityFiltersChange(srcEntity.key, filters)}
                          />
                        ) : (
                          <Stack
                            spacing={1}
                            sx={{
                              border: (t) => `1px solid ${t.palette.divider}`,
                              borderRadius: 1,
                              p: 2,
                            }}
                          >
                            <Typography variant="body2" fontWeight={600}>
                              {srcEntity.label}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {t_i18n('Configured in first occurrence')}
                            </Typography>
                            <FilterSummaryChips filters={filtersMap[srcEntity.key] ?? createEmptyFilterGroup()} />
                          </Stack>
                        )}
                      </Box>
                    )}
                    <Box sx={{ flex: '1 1 240px', minWidth: 0 }}>
                      <ConfiguredRuleEntityFilters
                        entityLabel={t_i18n(triplet.relationLabel)}
                        entityType={triplet.relationType}
                        resolvedEntityTypes={triplet.relationResolvedTypes}
                        fallbackEntityTypes={['stix-core-relationship']}
                        hideEntityTypeFilter={true}
                        blockedFilterKeys={[
                          'fromId',
                          'toId',
                          'fromOrToId',
                          'fromTypes',
                          'toTypes',
                          'fromRole',
                          'toRole',
                          'dynamicFrom',
                          'dynamicTo',
                          'relatedId',
                          'relatedType',
                        ]}
                        initialFilters={createEmptyFilterGroup()}
                        disabled={!canManage}
                        onFiltersChange={(filters) => handleEntityFiltersChange(relationshipKey, filters)}
                      />
                    </Box>
                    {tgtEntity && (
                      <Box sx={{ flex: '1 1 240px', minWidth: 0 }}>
                        {targetIsEditable ? (
                          <ConfiguredRuleEntityFilters
                            entityLabel={tgtEntity.label}
                            entityType={tgtEntity.entityType}
                            resolvedEntityTypes={tgtEntity.resolvedEntityTypes}
                            hideEntityTypeFilter={targetHasFixedType}
                            initialFilters={tgtEntity.initialFilters}
                            disabled={!canManage}
                            onFiltersChange={(filters) => handleEntityFiltersChange(tgtEntity.key, filters)}
                          />
                        ) : (
                          <Stack
                            spacing={1}
                            sx={{
                              border: (t) => `1px solid ${t.palette.divider}`,
                              borderRadius: 1,
                              p: 2,
                            }}
                          >
                            <Typography variant="body2" fontWeight={600}>
                              {tgtEntity.label}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {t_i18n('Configured in first occurrence')}
                            </Typography>
                            <FilterSummaryChips filters={filtersMap[tgtEntity.key] ?? createEmptyFilterGroup()} />
                          </Stack>
                        )}
                      </Box>
                    )}
                  </Box>
                );
              })}
          </Stack>

          {/* Inline preview while editing */}
          <Box sx={{ pt: 1 }}>
            <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: 'block' }}>
              {t_i18n('Preview')}
            </Typography>
            <Box
              sx={{
                border: (t) => `1px solid ${t.palette.divider}`,
                borderRadius: 1,
                p: 2,
                background: (t) => t.palette.background.default,
              }}
            >
              <ConfiguredRulePreview rule={rule} filtersMap={filtersMap} />
              {Object.values(filtersMap).every((fg) => (fg?.filters?.length ?? 0) === 0) && (
                <Typography variant="caption" color="text.secondary">
                  {t_i18n('No filters configured yet. Add filters above to see the preview.')}
                </Typography>
              )}
            </Box>
          </Box>
        </Stack>
      </AccordionDetails>
    </Accordion>
  );
};

interface RulesListItemProps {
  rule: NonNullable<Rule>;
  task: Task;
  toggle: () => void;
  onConfiguredRuleCountsChange?: (counts: { active: number; total: number }) => void;
}

const RulesListItem = ({
  rule,
  task,
  toggle,
  onConfiguredRuleCountsChange,
}: RulesListItemProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { platformModuleHelpers, schema } = useAuth();
  const isEnterpriseEdition = useEnterpriseEdition();
  const isEngineEnabled = platformModuleHelpers.isRuleEngineEnable();
  const canManageConfiguredRules = isEnterpriseEdition && isEngineEnabled;

  const [configuredRules, setConfiguredRules] = useState<ConfiguredRule[]>([]);
  const [configuredRuleToDelete, setConfiguredRuleToDelete] = useState<string | null>(null);

  const ruleEntities = useMemo(
    () => buildRuleEntities(rule, schema.schemaRelationsTypesMapping),
    [rule, schema.schemaRelationsTypesMapping],
  );

  const ruleStatus = isEngineEnabled && rule.activated ? t_i18n('Enabled') : t_i18n('Disabled');
  const taskWork = task?.work;
  const activeConfiguredRulesCount = configuredRules.filter((r) => r.active).length;
  const totalRuleCount = configuredRules.length > 0 ? configuredRules.length : 1;
  const activeRuleCount = configuredRules.length > 0
    ? activeConfiguredRulesCount
    : (rule.activated ? 1 : 0);

  const configuredRulePendingDeletion = configuredRules.find((r) => r.id === configuredRuleToDelete);

  useEffect(() => {
    onConfiguredRuleCountsChange?.({
      active: activeRuleCount,
      total: totalRuleCount,
    });
  }, [onConfiguredRuleCountsChange, activeRuleCount, totalRuleCount]);

  const handleAddConfiguredRule = () => {
    setConfiguredRules((previous) => [
      ...previous,
      {
        id: createId(),
        name: `${t_i18n('Configuration')} ${previous.length + 1}`,
        description: '',
        active: true,
        expanded: true,
      },
    ]);
  };

  const handleConfiguredRuleToggleExpanded = (id: string, expanded: boolean) => {
    setConfiguredRules((previous) => previous.map((configuredRule) => (
      configuredRule.id === id
        ? { ...configuredRule, expanded }
        : configuredRule
    )));
  };

  const handleConfiguredRuleChange = (
    id: string,
    data: Partial<Pick<ConfiguredRule, 'name' | 'description' | 'active'>>,
  ) => {
    setConfiguredRules((previous) => previous.map((configuredRule) => (
      configuredRule.id === id
        ? { ...configuredRule, ...data }
        : configuredRule
    )));
  };

  const handleDeleteConfiguredRule = () => {
    if (!configuredRuleToDelete) {
      return;
    }
    setConfiguredRules((previous) => previous.filter((configuredRule) => configuredRule.id !== configuredRuleToDelete));
    setConfiguredRuleToDelete(null);
  };

  const styleRuleRoot: CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
  };
  const styleRuleTitle: CSSProperties = {
    textWrap: 'nowrap',
    display: 'flex',
    alignItems: 'center',
    margin: 0,
  };
  const styleDefinition: CSSProperties = {
    display: 'flex',
    alignItems: 'stretch',
    gap: theme.spacing(4),
  };
  const styleIfThenBlock: CSSProperties = {
    flex: 1,
    border: `1px solid ${theme.palette.divider}`,
    borderRadius: Number(theme.shape.borderRadius),
    padding: theme.spacing(1.5),
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'center',
  };
  const styleStep: CSSProperties = {
    margin: theme.spacing(1),
    height: 50,
    minWidth: 400,
    display: 'flex',
    alignItems: 'center',
    textAlign: 'center',
    gap: theme.spacing(1),
  };

  return (
    <Grid container spacing={3} sx={{ marginBottom: 3 }}>
      <Grid size={{ xs: 3 }} sx={{ ...styleRuleRoot, alignSelf: 'stretch' }}>
        <DangerZoneBlock
          type="rules"
          displayTitle={false}
          title={t_i18n(rule.name)}
          sx={{ title: styleRuleTitle }}
          component={({ disabled, style, title }) => (
            <Card
              title={title}
              sx={style}
            >
              <Stack gap={2}>
                <div>
                  <Label>
                    {t_i18n('Description')}
                  </Label>
                  <span>{t_i18n(rule.description)}</span>
                </div>

                {configuredRules.length === 0 ? (
                  <div>
                    <Label>
                      {t_i18n('Status')}
                    </Label>
                    <FormGroup>
                      <FormControlLabel
                        label={ruleStatus}
                        control={(
                          <Switch
                            color="secondary"
                            disabled={!isEngineEnabled || disabled}
                            checked={isEngineEnabled && rule.activated}
                            onChange={toggle}
                          />
                        )}
                      />
                    </FormGroup>
                  </div>
                ) : (
                  <div>
                    <Label>
                      {t_i18n('Disable all')}
                    </Label>
                    <FormGroup>
                      <FormControlLabel
                        label={activeConfiguredRulesCount === 0 ? t_i18n('All disabled') : t_i18n('All active')}
                        control={(
                          <Switch
                            color="secondary"
                            disabled={!isEngineEnabled || disabled}
                            checked={isEngineEnabled && activeConfiguredRulesCount > 0}
                            onChange={() => {
                              const allDisabled = activeConfiguredRulesCount === 0;
                              setConfiguredRules((prev) => prev.map((r) => ({ ...r, active: allDisabled })));
                            }}
                          />
                        )}
                      />
                    </FormGroup>
                  </div>
                )}

                {configuredRules.length > 0 && (
                  <div>
                    <Label>
                      {t_i18n('Configured rules')}
                    </Label>
                    <span>
                      {activeConfiguredRulesCount}
                      /
                      {configuredRules.length}
                      {' '}
                      {t_i18n('active')}
                    </span>
                  </div>
                )}

                {isEngineEnabled && taskWork && (
                  <RuleListItemProgressBar taskEnable={task.enable ?? false} work={taskWork} />
                )}
              </Stack>
            </Card>
          )}
        />
      </Grid>
      <Grid size={{ xs: 9 }}>
        <Stack spacing={3}>
          <Card
            sx={{ overflowX: 'auto', minWidth: 0 }}
            title=" "
          >
            <Box
              sx={{
                borderRadius: 1,
                p: 2,
              }}
            >
              {canManageConfiguredRules && (
                <Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 1.5 }}>
                  <Button
                    size="small"
                    variant="secondary"
                    onClick={handleAddConfiguredRule}
                    startIcon={<AddOutlined fontSize="small" />}
                  >
                    {t_i18n('Add configuration')}
                  </Button>
                </Box>
              )}

              <div style={styleDefinition}>
                <div style={styleIfThenBlock}>
                  {(rule.display?.if ?? []).map((step, index) => (
                    <div key={index} style={styleStep}>
                      <span style={{ width: '30px', flexShrink: 0 }}>{t_i18n('IF')}</span>
                      <RuleTag color={step?.source_color} label={step?.source} />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <span>{t_i18n(step?.relation)}</span>
                      </div>
                      <RuleTag color={step?.target_color} label={step?.target} />
                    </div>
                  ))}
                </div>
                <div style={{ textAlign: 'center', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
                  <ArrowRightAlt fontSize="large" />
                  <span style={{ width: '80px' }}>{t_i18n('THEN')}</span>
                </div>
                <div style={styleIfThenBlock}>
                  {(rule.display?.then ?? []).map((step, index) => {
                    return (
                      <div key={index} style={styleStep}>
                        <RuleTag action label={step?.action} />
                        <RuleTag color={step?.source_color} label={step?.source} />
                        {step?.relation && (
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <span>{t_i18n(step?.relation)}</span>
                          </div>
                        )}
                        {step?.target && <RuleTag color={step?.target_color} label={step?.target} />}
                      </div>
                    );
                  })}
                </div>
              </div>
            </Box>
          </Card>

          {configuredRules.length > 0 && (
            <Card title={t_i18n('Configured rules')}>
              <Stack spacing={1.5}>
                {configuredRules.map((configuredRule) => (
                  <ConfiguredRuleAccordion
                    key={configuredRule.id}
                    configuredRule={configuredRule}
                    rule={rule}
                    ruleEntities={ruleEntities}
                    canManage={canManageConfiguredRules}
                    onChange={handleConfiguredRuleChange}
                    onToggleExpand={handleConfiguredRuleToggleExpanded}
                    onDelete={(id) => setConfiguredRuleToDelete(id)}
                  />
                ))}
              </Stack>
            </Card>
          )}
        </Stack>
      </Grid>

      <Dialog
        open={Boolean(configuredRulePendingDeletion)}
        onClose={() => setConfiguredRuleToDelete(null)}
        title={t_i18n('Delete configuration')}
        size="small"
      >
        <Typography>
          {t_i18n('Are you sure you want to delete this configured rule?')}
          {configuredRulePendingDeletion && (
            <>
              {' '}
              <strong>{configuredRulePendingDeletion.name}</strong>
            </>
          )}
        </Typography>
        <DialogActions>
          <Button variant="secondary" onClick={() => setConfiguredRuleToDelete(null)}>
            {t_i18n('Cancel')}
          </Button>
          <Button intent="destructive" onClick={handleDeleteConfiguredRule}>
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </Grid>
  );
};

export default RulesListItem;
