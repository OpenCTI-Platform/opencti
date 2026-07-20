import React, { CSSProperties, useEffect, useMemo, useRef, useState } from 'react';
import { Stack } from '@mui/material';
import Box from '@mui/material/Box';
import DangerZoneBlock from '@components/common/danger_zone/DangerZoneBlock';
import FormGroup from '@mui/material/FormGroup';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import { AddOutlined, ArrowRightAlt, DeleteOutline, ExpandMore, FilterAltOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import Typography from '@mui/material/Typography';
import TextField from '@mui/material/TextField';
import Tooltip from '@mui/material/Tooltip';
import Divider from '@mui/material/Divider';
import Collapse from '@mui/material/Collapse';
import Chip from '@mui/material/Chip';
import IconButton from '@mui/material/IconButton';
import MenuItem from '@mui/material/MenuItem';
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
import { RULES_CONFIGURED_LOCAL_STORAGE_KEY } from './rules-utils';
import { RULE_CAPABILITIES, RuleCapability, RuleSlotCapability } from './rule-capabilities.generated';
import { getEligibleConditionFamilies, getLockedEntityTypeFilterValues } from './rule-condition-policy';
import RuleConditionBuilder, { RuleConditionBuilderHandle } from './RuleConditionBuilder';

// ─── Debug error boundary ─────────────────────────────────────────────────────
class AccordionErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { error: Error | null }
> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('[AccordionErrorBoundary] Render crash:', error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <Box sx={{ p: 2, color: 'error.main', border: '1px solid', borderRadius: 1, fontSize: '0.75rem' }}>
          Configuration render error — check browser console for details.
        </Box>
      );
    }
    return this.props.children;
  }
}

interface ConfiguredRule {
  id: string;
  name: string;
  description: string;
  active: boolean;
  expanded: boolean;
  filtersMap: Record<string, FilterGroup>;
  outputRelationType: string;
  outputConfidenceMode: 'avg' | 'max' | 'fixed';
  outputConfidenceFixed: number;
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

type ConditionSlotKind = 'entity' | 'relationship';

interface PreviewConditionSlot {
  key: string;
  label: string;
  kind: ConditionSlotKind;
}

interface ConditionEditorSlot extends PreviewConditionSlot {
  resolvedEntityTypes: string[];
  fallbackEntityTypes?: string[];
  blockedFilterKeys?: string[];
  forcedAvailableFilterKeys?: string[];
}

interface TypeFamilyOption {
  id: string;
  label: string;
  entityTypes: string[];
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
  mode: filterGroup.mode ?? 'and',
  filters: (filterGroup.filters ?? []).map((filter) => ({
    ...filter,
    values: [...(filter.values ?? [])],
  })),
  filterGroups: (filterGroup.filterGroups ?? []).map(cloneFilterGroup),
});

const defaultOutputRelationType = (rule: NonNullable<Rule>) => {
  const relation = rule.display?.then?.[0]?.relation ?? '';
  return relation.replace(/^relationship_/, '').trim();
};

const hydrateConfiguredRule = (
  rule: NonNullable<Rule>,
  configuredRule: Partial<ConfiguredRule>,
  defaultFiltersMap: Record<string, FilterGroup>,
): ConfiguredRule => {
  const outputRelationType = configuredRule.outputRelationType ?? defaultOutputRelationType(rule);
  const outputConfidenceMode = configuredRule.outputConfidenceMode ?? 'avg';
  const outputConfidenceFixed = typeof configuredRule.outputConfidenceFixed === 'number'
    ? configuredRule.outputConfidenceFixed
    : 50;
  const filtersMap = Object.entries(defaultFiltersMap).reduce<Record<string, FilterGroup>>((acc, [key, fallback]) => {
    const existing = configuredRule.filtersMap?.[key];
    acc[key] = existing ? cloneFilterGroup(existing) : cloneFilterGroup(fallback);
    return acc;
  }, {});
  return {
    id: configuredRule.id ?? createId(),
    name: configuredRule.name ?? 'Configuration',
    description: configuredRule.description ?? '',
    active: configuredRule.active ?? true,
    expanded: configuredRule.expanded ?? true,
    filtersMap,
    outputRelationType,
    outputConfidenceMode,
    outputConfidenceFixed,
  };
};

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

const getFilterGroupSignature = (filterGroup: FilterGroup): string => JSON.stringify(filterGroup);

const mergeFiltersByKey = (input: FilterGroup, lockedFilters: Filter[]): FilterGroup => {
  if (lockedFilters.length === 0) return input;
  const byKey = new Map<string, Filter>();
  (input.filters ?? []).forEach((filter) => {
    byKey.set(filter.key, filter);
  });
  lockedFilters.forEach((filter) => {
    byKey.set(filter.key, {
      ...filter,
      values: [...filter.values],
    });
  });
  return {
    ...input,
    filters: Array.from(byKey.values()),
  };
};

const LOCATION_TYPE_NAMES = new Set([
  'location',
  'country',
  'region',
  'city',
  'administrative-area',
  'position',
]);

const IDENTITY_TYPE_NAMES = new Set([
  'identity',
  'organization',
  'individual',
  'sector',
  'system',
]);

const uniqueSorted = (values: string[]) => Array.from(new Set(values)).sort();

const intersectCaseInsensitive = (left: string[], right: string[]): string[] => {
  const rightLower = new Set(right.map((value) => value.toLowerCase()));
  return left.filter((value) => rightLower.has(value.toLowerCase()));
};

const classifyTypeFamily = (
  value: string,
  schemaScoTypesLower: Set<string>,
): 'indicator' | 'observable' | 'identity' | 'location' | 'relationship' | 'entity' => {
  const lower = value.toLowerCase();
  if (lower.includes('relationship')) return 'relationship';
  if (lower.includes('indicator')) return 'indicator';
  if (lower.includes('observable') || lower.includes('stix-cyber-observable') || schemaScoTypesLower.has(lower)) {
    return 'observable';
  }
  if (IDENTITY_TYPE_NAMES.has(lower) || lower.includes('identity')) return 'identity';
  if (LOCATION_TYPE_NAMES.has(lower) || lower.includes('location')) return 'location';
  return 'entity';
};

const buildTypeFamilyOptions = (
  kind: ConditionSlotKind,
  types: string[],
  schemaScoTypes: string[],
): TypeFamilyOption[] => {
  const uniqueTypes = uniqueSorted(types);
  if (uniqueTypes.length === 0) return [];
  if (kind === 'relationship') {
    return [{
      id: 'relationship',
      label: 'Relationship type',
      entityTypes: uniqueTypes,
    }];
  }

  const schemaScoTypesLower = new Set(schemaScoTypes.map((sco) => sco.toLowerCase()));
  const families = new Map<TypeFamilyOption['id'], string[]>();
  uniqueTypes.forEach((type) => {
    const family = classifyTypeFamily(type, schemaScoTypesLower);
    const existing = families.get(family) ?? [];
    families.set(family, [...existing, type]);
  });

  const options: TypeFamilyOption[] = [{
    id: 'entity',
    label: 'Entity type',
    entityTypes: uniqueTypes,
  }];

  const orderedFamilies: Array<{ id: TypeFamilyOption['id']; label: string }> = [
    { id: 'indicator', label: 'Indicator type' },
    { id: 'observable', label: 'Observable type' },
    { id: 'identity', label: 'Identity type' },
    { id: 'location', label: 'Location type' },
  ];

  orderedFamilies.forEach((family) => {
    const familyTypes = uniqueSorted(families.get(family.id) ?? []);
    if (familyTypes.length > 0) {
      options.push({
        id: family.id,
        label: family.label,
        entityTypes: familyTypes,
      });
    }
  });

  return options;
};

interface ConfiguredRuleEntityFiltersProps {
  entityLabel: string;
  resolvedEntityTypes: string[];
  headerContent?: React.ReactNode;
  fallbackEntityTypes?: string[];
  hideEntityTypeFilter?: boolean;
  blockedFilterKeys?: string[];
  forcedAvailableFilterKeys?: string[];
  lockedFilters?: Filter[];
  initialFilters: FilterGroup;
  disabled: boolean;
  onFiltersChange: (filters: FilterGroup) => void;
}

const ConfiguredRuleEntityFilters = ({
  entityLabel,
  resolvedEntityTypes,
  headerContent,
  fallbackEntityTypes = ['Stix-Core-Object'],
  hideEntityTypeFilter = false,
  blockedFilterKeys = [],
  forcedAvailableFilterKeys,
  lockedFilters = [],
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
    const visible = rawAvailableFilterKeys.filter((key) => !blockedKeys.has(key.toLowerCase()));
    if (!forcedAvailableFilterKeys || forcedAvailableFilterKeys.length === 0) {
      return visible;
    }
    const forcedLower = new Set(forcedAvailableFilterKeys.map((k) => k.toLowerCase()));
    return visible.filter((key) => forcedLower.has(key.toLowerCase()));
  }, [rawAvailableFilterKeys, hideEntityTypeFilter, blockedFilterKeys, forcedAvailableFilterKeys]);
  const searchEntityTypes = resolvedEntityTypes.length > 0 ? resolvedEntityTypes : fallbackEntityTypes;

  const mergeLockedFilters = (input: FilterGroup): FilterGroup => {
    if (!lockedFilters.length) return input;
    const byKey = new Map<string, Filter>();
    (input.filters ?? []).forEach((filter) => {
      byKey.set(filter.key, filter);
    });
    lockedFilters.forEach((filter) => {
      byKey.set(filter.key, {
        ...filter,
        values: [...filter.values],
      });
    });
    return {
      ...input,
      filters: Array.from(byKey.values()),
    };
  };

  const initialFilterState = useMemo(() => {
    const withLockedFilters = mergeLockedFilters(cloneFilterGroup(initialFilters));
    const sanitized = removeIdAndIncorrectKeysFromFilterGroupObject(
      withLockedFilters,
      availableFilterKeys,
    );
    return sanitized ?? mergeLockedFilters(createEmptyFilterGroup());
  }, [initialFilters, availableFilterKeys, lockedFilters]);
  const [filters, filterHelpers] = useFiltersState(initialFilterState);

  // Notify parent when filter state changes
  const isFirstRender = React.useRef(true);
  useEffect(() => {
    const sanitizedFilters = removeIdAndIncorrectKeysFromFilterGroupObject(filters, availableFilterKeys)
      ?? createEmptyFilterGroup();
    const finalFilters = mergeLockedFilters(sanitizedFilters);
    if (isFirstRender.current) {
      isFirstRender.current = false;
      // Still call on mount so parent's map is initialised with preset filters
      onFiltersChange(finalFilters);
      return;
    }
    onFiltersChange(finalFilters);
  }, [filters, availableFilterKeys, lockedFilters]);

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
      {headerContent}
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

const FilterSummaryChips = ({
  filters,
  onDelete,
}: {
  filters: FilterGroup;
  onDelete?: (filter: Filter) => void;
}) => {
  const theme = useTheme<Theme>();
  const activeFilters: Filter[] = filters.filters ?? [];
  if (activeFilters.length === 0) return null;
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.75, mt: 0.5, width: '100%' }}>
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
            onDelete={onDelete
              ? (event) => {
                  event.stopPropagation();
                  onDelete(f);
                }
              : undefined}
            sx={{
              fontSize: '0.75rem',
              height: 28,
              borderRadius: 1,
              width: '100%',
              justifyContent: 'flex-start',
              color: theme.palette.text.primary,
              backgroundColor: theme.palette.background.paper,
              borderColor: theme.palette.divider,
              '& .MuiChip-label': {
                paddingInline: 1.25,
                flex: 1,
              },
            }}
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
  showWhenEmpty?: boolean;
  canManage?: boolean;
  editableEntityKeys?: Set<string>;
  onAddCondition?: (slot: PreviewConditionSlot) => void;
  onRemoveCondition?: (slotKey: string, filter: Filter) => void;
  withTopDivider?: boolean;
}

const ConfiguredRulePreview = ({
  rule,
  filtersMap,
  showWhenEmpty = false,
  canManage = false,
  editableEntityKeys,
  onAddCondition,
  onRemoveCondition,
  withTopDivider = true,
}: ConfiguredRulePreviewProps) => {
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
  if (!showWhenEmpty && !hasAnyFilters) return null;

  const resolveEntitySlot = (rawLabel?: string | null): PreviewConditionSlot | null => {
    if (!rawLabel) return null;
    const { type, identifier } = parseDisplayLabel(rawLabel);
    if (!type) return null;
    const key = `${type}::${identifier ?? ''}`;
    return {
      key,
      label: `${type}${identifier ? ` ${identifier}` : ''}`,
      kind: 'entity',
    };
  };

  const renderAddConditionButton = (
    slot: PreviewConditionSlot | null,
    disabled = false,
  ) => {
    if (!slot || !canManage || !onAddCondition) return null;
    return (
      <Tooltip title="add condition">
        <span>
          <IconButton
            size="small"
            onClick={(event) => {
              event.stopPropagation();
              onAddCondition(slot);
            }}
            disabled={disabled}
          >
            <AddOutlined fontSize="small" />
          </IconButton>
        </span>
      </Tooltip>
    );
  };

  const renderEntityTagWithAddCondition = (
    label: string | null | undefined,
    color: string | null | undefined,
    slot: PreviewConditionSlot | null,
    disabled = false,
  ) => {
    if (!label) return null;
    const canRenderAddButton = !!slot && canManage && !!onAddCondition && !disabled;
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'stretch', gap: 0.75, width: '100%' }}>
        <RuleTag color={color} label={label} />
        {canRenderAddButton && (
          <Tooltip title={t_i18n('Add condition')}>
            <Box
              role="button"
              tabIndex={0}
              onClick={(event) => {
                event.stopPropagation();
                onAddCondition(slot);
              }}
              onKeyDown={(event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                  event.stopPropagation();
                  onAddCondition(slot);
                }
              }}
              sx={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'flex-start',
                gap: 0.75,
                height: 30,
                px: 1,
                borderRadius: 1,
                cursor: 'pointer',
                color: 'primary.main',
                border: (t) => `1px dashed ${t.palette.primary.main}`,
                backgroundColor: 'transparent',
                '&:hover': {
                  backgroundColor: (t) => t.palette.action.hover,
                },
              }}
            >
              <FilterAltOutlined sx={{ fontSize: 16 }} />
              <Typography variant="caption" sx={{ fontWeight: 500 }}>
                {t_i18n('Add Condition')}
              </Typography>
            </Box>
          </Tooltip>
        )}
      </Box>
    );
  };

  const styleStepPrimaryRow: CSSProperties = {
    display: 'grid',
    gridTemplateColumns: '72px minmax(0, 1fr) minmax(0, 1fr) minmax(0, 1fr)',
    alignItems: 'center',
    columnGap: theme.spacing(1),
    padding: `${theme.spacing(0.5)} ${theme.spacing(0.5)} 0`,
    width: '100%',
    minHeight: 28,
  };

  const styleStepConditionsRow: CSSProperties = {
    display: 'grid',
    gridTemplateColumns: '72px minmax(0, 1fr) minmax(0, 1fr) minmax(0, 1fr)',
    alignItems: 'flex-start',
    columnGap: theme.spacing(1),
    padding: `0 ${theme.spacing(0.5)} ${theme.spacing(0.5)}`,
    width: '100%',
  };

  const renderProgramToken = (label: string | null | undefined) => {
    if (!label) return null;
    return (
      <Box
        sx={{
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          minWidth: 56,
          height: 30,
          px: 1.25,
          borderRadius: 1,
          backgroundColor: 'rgba(0, 0, 0, 0.35)',
          border: (t) => `1px solid ${t.palette.divider}`,
          color: (t) => t.palette.text.primary,
          fontSize: '0.85rem',
          fontWeight: 600,
          textTransform: 'uppercase',
          letterSpacing: '0.04em',
        }}
      >
        {label}
      </Box>
    );
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

  const styleThenPreviewBlock: CSSProperties = {
    ...stylePreviewBlock,
    justifyContent: 'center',
  };

  return (
    <Box
      sx={{
        mt: withTopDivider ? 1 : 0,
        pt: withTopDivider ? 1 : 0,
        borderTop: withTopDivider ? (t) => `1px solid ${t.palette.divider}` : 'none',
        width: '100%',
      }}
      onClick={(e) => e.stopPropagation()}
    >
      <Box sx={{ display: 'flex', alignItems: 'stretch', gap: 2, flexWrap: 'wrap' }}>
        {/* IF block */}
        <Box style={stylePreviewBlock}>
          {(() => {
            let relationshipTripletIndex = 0;
            return (rule.display?.if ?? []).map((step, index) => {
              const isPropertyStep = step?.relation === 'relationship_has';
              const sourceSlot = resolveEntitySlot(step?.source);
              const sourceEditable = sourceSlot
                ? (editableEntityKeys ? editableEntityKeys.has(sourceSlot.key) : true)
                : false;
              const targetSlot = !isPropertyStep ? resolveEntitySlot(step?.target) : null;
              const targetEditable = targetSlot
                ? (editableEntityKeys ? editableEntityKeys.has(targetSlot.key) : true)
                : false;
              const relationshipSlot = !isPropertyStep
                ? {
                    key: `relationship::triplet-${relationshipTripletIndex}`,
                    label: t_i18n(step?.relation ?? 'Relationship'),
                    kind: 'relationship' as const,
                  }
                : null;
              if (!isPropertyStep) {
                relationshipTripletIndex += 1;
              }
              return (
                <Box key={index}>
                  <Box sx={styleStepPrimaryRow}>
                    <Box sx={{ minWidth: 0 }}>
                      {renderProgramToken(t_i18n('IF'))}
                    </Box>
                    <Box sx={{ minWidth: 0, display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 0.5 }}>
                      {renderEntityTagWithAddCondition(step?.source, step?.source_color, sourceSlot, !sourceEditable)}
                    </Box>
                    <Box sx={{ minWidth: 0, display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 0.5 }}>
                      {step?.relation && (
                        <Typography variant="caption" color="text.secondary" sx={{ textAlign: 'center' }}>
                          {t_i18n(step.relation)}
                        </Typography>
                      )}
                      {renderAddConditionButton(relationshipSlot)}
                    </Box>
                    <Box sx={{ minWidth: 0, display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 0.5 }}>
                      {step?.target && step?.relation !== 'relationship_has'
                        && renderEntityTagWithAddCondition(step.target, step.target_color, targetSlot, !targetEditable)}
                    </Box>
                  </Box>

                  <Box sx={styleStepConditionsRow}>
                    <Box sx={{ minWidth: 0 }} />
                    <Box sx={{ minWidth: 0 }}>
                      <FilterSummaryChips
                        filters={getFilters(step?.source) ?? createEmptyFilterGroup()}
                        onDelete={canManage && onRemoveCondition && sourceSlot && sourceEditable
                          ? (filter) => onRemoveCondition(sourceSlot.key, filter)
                          : undefined}
                      />
                    </Box>
                    <Box sx={{ minWidth: 0 }}>
                      <FilterSummaryChips
                        filters={relationshipSlot ? (filtersMap[relationshipSlot.key] ?? createEmptyFilterGroup()) : createEmptyFilterGroup()}
                        onDelete={canManage && onRemoveCondition && relationshipSlot
                          ? (filter) => onRemoveCondition(relationshipSlot.key, filter)
                          : undefined}
                      />
                    </Box>
                    <Box sx={{ minWidth: 0 }}>
                      {step?.target && step?.relation !== 'relationship_has' && (
                        <FilterSummaryChips
                          filters={getFilters(step.target) ?? createEmptyFilterGroup()}
                          onDelete={canManage && onRemoveCondition && targetSlot && targetEditable
                            ? (filter) => onRemoveCondition(targetSlot.key, filter)
                            : undefined}
                        />
                      )}
                    </Box>
                  </Box>
                </Box>
              );
            });
          })()}
        </Box>

        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <ArrowRightAlt />
          {renderProgramToken(t_i18n('THEN'))}
        </Box>

        {/* THEN block */}
        <Box style={styleThenPreviewBlock}>
          {(rule.display?.then ?? []).map((step, index) => (
            <Box key={index} sx={styleStepPrimaryRow}>
              <Box sx={{ minWidth: 0, display: 'flex', justifyContent: 'flex-start' }}>
                {renderProgramToken(step?.action ?? undefined)}
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
  schemaSdoTypes: string[];
  schemaScoTypes: string[];
  canManage: boolean;
  onChange: (id: string, data: Partial<Pick<ConfiguredRule, 'name' | 'description' | 'active'>>) => void;
  onFiltersMapChange: (id: string, slotKey: string, filters: FilterGroup) => void;
  onToggleExpand: (id: string, expanded: boolean) => void;
  onDelete: (id: string) => void;
}

const ConfiguredRuleAccordion = ({
  configuredRule,
  rule,
  ruleEntities,
  schemaSdoTypes,
  schemaScoTypes,
  canManage,
  onChange,
  onFiltersMapChange,
  onToggleExpand,
  onDelete,
}: ConfiguredRuleAccordionProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const ruleTriplets = useMemo(() => buildRuleTriplets(rule), [rule]);

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

  const filtersMap = configuredRule.filtersMap;
  const hasAnyConditions = Object.values(filtersMap).some((fg) => (fg?.filters?.length ?? 0) > 0);
  const isSightingIncidentRule = rule.name === 'Raise incident based on sighting';
  const genericEntityTypeOptions = useMemo(() => {
    const types = [...schemaSdoTypes, ...schemaScoTypes];
    return Array.from(new Set(types)).sort();
  }, [schemaSdoTypes, schemaScoTypes]);

  const [conditionEditorSlot, setConditionEditorSlot] = useState<ConditionEditorSlot | null>(null);
  const [conditionEditorDraftFilters, setConditionEditorDraftFilters] = useState<FilterGroup>(createEmptyFilterGroup());
  const conditionBuilderRef = useRef<RuleConditionBuilderHandle | null>(null);

  // Once a rule is activated it becomes read-only: no condition, name or description editing.
  const isEditable = canManage && !configuredRule.active;

  const [confirmAction, setConfirmAction] = useState<'activate' | 'deactivate' | 'delete' | null>(null);

  const handleConfirmAction = () => {
    if (confirmAction === 'activate') {
      onChange(configuredRule.id, { active: true });
    } else if (confirmAction === 'deactivate') {
      onChange(configuredRule.id, { active: false });
    } else if (confirmAction === 'delete') {
      onDelete(configuredRule.id);
    }
    setConfirmAction(null);
  };

  const handleToggleActive = (checked: boolean) => {
    setConfirmAction(checked ? 'activate' : 'deactivate');
  };

  const confirmActionMessage = (() => {
    switch (confirmAction) {
      case 'activate':
        return t_i18n('Are you sure? Once the rule is activated all data in the platform will be processed by this rule and you will no longer be able to edit it.');
      case 'deactivate':
        return t_i18n('Are you sure you want to deactivate this rule? This will remove all relationships created by the rule.');
      case 'delete':
        return configuredRule.active
          ? t_i18n('Are you sure you want to delete this rule? This will remove all relationships created by the rule.')
          : t_i18n('Are you sure you want to delete this rule?');
      default:
        return '';
    }
  })();

  const editableEntityKeys = useMemo(
    () => new Set(Array.from(firstTripletForEntity.entries()).map(([entityKey]) => entityKey)),
    [firstTripletForEntity],
  );

  const resolveEditorEntityTypes = (resolvedTypes: string[]) => {
    const normalizedResolved = uniqueSorted(resolvedTypes);
    const hasOnlyGeneric = normalizedResolved.length === 0
      || normalizedResolved.every((t) => ['stix-core-object', 'entity', 'observable'].includes(t.toLowerCase()));
    if (hasOnlyGeneric) {
      return genericEntityTypeOptions;
    }
    return normalizedResolved;
  };

  const handleAddCondition = (slot: PreviewConditionSlot) => {
    if (!isEditable) return;
    if (slot.kind === 'entity' && !editableEntityKeys.has(slot.key)) {
      return;
    }

    setConditionEditorDraftFilters(cloneFilterGroup(filtersMap[slot.key] ?? createEmptyFilterGroup()));

    if (slot.kind === 'entity') {
      const entity = entitiesByKey.get(slot.key);
      const resolvedEntityTypes = resolveEditorEntityTypes(entity?.resolvedEntityTypes ?? []);
      setConditionEditorSlot({
        ...slot,
        resolvedEntityTypes,
        fallbackEntityTypes: resolvedEntityTypes,
      });
      return;
    }

    const tripletKey = slot.key.replace(/^relationship::/, '');
    const triplet = ruleTriplets.find((candidate) => candidate.key === tripletKey);
    const relationType = triplet?.relationType.toLowerCase() ?? '';
    const isSightingTriplet = isSightingIncidentRule && relationType === 'stix-sighting-relationship';
    setConditionEditorSlot({
      ...slot,
      resolvedEntityTypes: triplet?.relationResolvedTypes ?? ['stix-core-relationship'],
      fallbackEntityTypes: ['stix-core-relationship'],
      forcedAvailableFilterKeys: isSightingTriplet
        ? ['first_seen', 'last_seen', 'confidence']
        : (relationType === 'related-to' ? ['start_time', 'stop_time', 'confidence', 'objectMarking'] : undefined),
      blockedFilterKeys: [
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
      ],
    });
  };

  const handleRemoveCondition = (slotKey: string, filter: Filter) => {
    if (!isEditable) return;
    const currentGroup = filtersMap[slotKey] ?? createEmptyFilterGroup();
    const nextGroup: FilterGroup = {
      ...currentGroup,
      filters: (currentGroup.filters ?? []).filter((candidate) => candidate.id !== filter.id),
    };
    const sanitized = sanitizeConditionEditorFiltersForPersistence(nextGroup);
    onFiltersMapChange(configuredRule.id, slotKey, sanitized);
  };

  const ruleCapability = useMemo<RuleCapability | null>(() => {
    const direct = RULE_CAPABILITIES[rule.id];
    if (direct) {
      return direct;
    }
    return Object.values(RULE_CAPABILITIES).find((candidate) => candidate.ruleName === rule.name) ?? null;
  }, [rule.id, rule.name]);

  const slotCapability = useMemo<RuleSlotCapability | null>(() => {
    if (!conditionEditorSlot || !ruleCapability) return null;
    if (conditionEditorSlot.kind === 'entity') {
      const { identifier } = parseDisplayLabel(conditionEditorSlot.label);
      if (identifier) {
        return ruleCapability.slots.find((slot) => slot.kind === 'entity' && slot.id === identifier) ?? null;
      }
      return null;
    }
    const relationshipSlots = ruleCapability.slots.filter((slot) => slot.kind === 'relationship');
    if (relationshipSlots.length === 0) return null;
    const tripletKey = conditionEditorSlot.key.replace(/^relationship::triplet-/, '');
    const tripletIndex = Number.parseInt(tripletKey, 10);
    if (Number.isNaN(tripletIndex)) {
      return relationshipSlots[0] ?? null;
    }
    return relationshipSlots[tripletIndex] ?? relationshipSlots[0] ?? null;
  }, [conditionEditorSlot, ruleCapability]);

  const isMultiTypeEntitySlot = conditionEditorSlot?.kind === 'entity' && Boolean(slotCapability?.multiType);

  const conditionEditorSearchTypes = useMemo(() => {
    if (!conditionEditorSlot) return ['Stix-Core-Object'];
    return conditionEditorSlot.resolvedEntityTypes.length > 0
      ? conditionEditorSlot.resolvedEntityTypes
      : (conditionEditorSlot.fallbackEntityTypes ?? ['Stix-Core-Object']);
  }, [conditionEditorSlot]);

  const editorAvailableFilterKeys = useAvailableFilterKeysForEntityTypes(conditionEditorSearchTypes);

  const eligibleConditionPolicyFamilies = useMemo(() => {
    if (!ruleCapability || !slotCapability || !conditionEditorSlot) return [];
    return getEligibleConditionFamilies(ruleCapability, slotCapability, editorAvailableFilterKeys);
  }, [ruleCapability, slotCapability, conditionEditorSlot, editorAvailableFilterKeys]);

  const displayedConditionPolicyFamilies = useMemo(
    () => eligibleConditionPolicyFamilies.filter((family) => family.id !== 'entity-type-restriction'),
    [eligibleConditionPolicyFamilies],
  );

  const effectiveForcedAvailableFilterKeys = useMemo(() => {
    const policyKeys = uniqueSorted(displayedConditionPolicyFamilies.flatMap((family) => family.availableFilterKeys));
    const slotForced = conditionEditorSlot?.forcedAvailableFilterKeys ?? [];
    if (policyKeys.length > 0 && slotForced.length > 0) {
      return intersectCaseInsensitive(slotForced, policyKeys);
    }
    if (policyKeys.length > 0) return policyKeys;
    if (slotForced.length > 0) return slotForced;
    return undefined;
  }, [displayedConditionPolicyFamilies, conditionEditorSlot]);

  const effectiveLockedEntityTypes = useMemo(() => {
    if (!conditionEditorSlot || conditionEditorSlot.kind !== 'entity') return [];
    const policyLocked = slotCapability ? getLockedEntityTypeFilterValues(slotCapability) : [];
    if (policyLocked.length > 0) return policyLocked;
    const normalized = uniqueSorted(conditionEditorSlot.resolvedEntityTypes);
    return normalized;
  }, [slotCapability, conditionEditorSlot]);

  const sanitizeConditionEditorFiltersForPersistence = (input: FilterGroup): FilterGroup => {
    if (!conditionEditorSlot) {
      return cloneFilterGroup(input);
    }

    const blockedKeys = new Set(
      ['regardingOf', 'dynamicRegardingOf', ...(conditionEditorSlot.blockedFilterKeys ?? [])].map((k) => k.toLowerCase()),
    );
    if (conditionEditorSlot.kind === 'entity') {
      blockedKeys.add('relationship_type');
      blockedKeys.add('fromTypes');
      blockedKeys.add('toTypes');
    }

    const candidateKeys = effectiveForcedAvailableFilterKeys && effectiveForcedAvailableFilterKeys.length > 0
      ? effectiveForcedAvailableFilterKeys
      : editorAvailableFilterKeys;
    const availableKeys = candidateKeys.filter((key) => !blockedKeys.has(key.toLowerCase()));
    const sanitized = removeIdAndIncorrectKeysFromFilterGroupObject(
      cloneFilterGroup(input),
      availableKeys,
    ) ?? createEmptyFilterGroup();

    const lockedFilters: Filter[] = (conditionEditorSlot.kind === 'entity' && !isMultiTypeEntitySlot && effectiveLockedEntityTypes.length > 0)
      ? [{
          key: 'entity_type',
          values: effectiveLockedEntityTypes,
          operator: 'eq',
          mode: 'or',
        }]
      : [];

    return mergeFiltersByKey(sanitized, lockedFilters);
  };

  const closeConditionEditor = () => {
    conditionBuilderRef.current = null;
    setConditionEditorSlot(null);
    setConditionEditorDraftFilters(createEmptyFilterGroup());
  };

  return (
    <Accordion
      expanded={configuredRule.expanded}
      onChange={(_, expanded) => onToggleExpand(configuredRule.id, expanded)}
      slotProps={{ transition: { unmountOnExit: false } }}
    >
      <AccordionSummary
        expandIcon={<ExpandMore />}
        sx={{
          alignItems: 'flex-start',
          '& .MuiAccordionSummary-content': {
            alignItems: 'flex-start',
            marginY: 1,
            paddingRight: 2,
          },
          '& .MuiAccordionSummary-expandIconWrapper': {
            alignSelf: 'flex-start',
            marginTop: 2,
            marginRight: 0.5,
          },
        }}
      >
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
                    onChange={(_, checked) => handleToggleActive(checked)}
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
                      setConfirmAction('delete');
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
            hasAnyConditions ? (
              <ConfiguredRulePreview
                rule={rule}
                filtersMap={filtersMap}
              />
            ) : (
              configuredRule.description && (
                <Typography variant="body2" color="text.secondary">
                  {configuredRule.description}
                </Typography>
              )
            )
          )}
        </Box>
      </AccordionSummary>

      <AccordionDetails sx={{ pt: 0.5 }}>
        <Stack spacing={1.5}>
          <TextField
            fullWidth
            label={t_i18n('Rule Configuration Name')}
            value={configuredRule.name}
            onChange={(event) => onChange(configuredRule.id, { name: event.target.value })}
            size="small"
            disabled={!isEditable}
          />

          <TextField
            fullWidth
            multiline
            minRows={2}
            label={t_i18n('Rule Configuration Description')}
            value={configuredRule.description}
            onChange={(event) => onChange(configuredRule.id, { description: event.target.value })}
            size="small"
            disabled={!isEditable}
          />

          <Box>
            <Box
              sx={{
                border: (t) => `1px solid ${t.palette.divider}`,
                borderRadius: 1,
                p: 2,
                background: (t) => t.palette.background.default,
              }}
            >
              <ConfiguredRulePreview
                rule={rule}
                filtersMap={filtersMap}
                showWhenEmpty
                canManage={isEditable}
                editableEntityKeys={editableEntityKeys}
                onAddCondition={handleAddCondition}
                onRemoveCondition={handleRemoveCondition}
                withTopDivider={false}
              />
            </Box>
          </Box>

        </Stack>

        <Dialog
          open={Boolean(conditionEditorSlot)}
          onClose={closeConditionEditor}
          title={conditionEditorSlot
            ? `${t_i18n(conditionEditorSlot.kind === 'relationship'
              ? 'Add condition on relationship'
              : 'Add condition on')} ${t_i18n(conditionEditorSlot.label)}`
            : t_i18n('Add condition')}
          size="large"
        >
          <Stack spacing={2} sx={{ pt: 0.5 }}>
            {conditionEditorSlot && (
              <>
                <RuleConditionBuilder
                  ref={conditionBuilderRef}
                  key={conditionEditorSlot.key}
                  slotKind={conditionEditorSlot.kind}
                  allowedEntityTypes={effectiveLockedEntityTypes.length > 0
                    ? effectiveLockedEntityTypes
                    : conditionEditorSlot.resolvedEntityTypes}
                  isMultiType={isMultiTypeEntitySlot}
                  showEntityTypeRow={conditionEditorSlot.kind === 'entity' && isMultiTypeEntitySlot}
                  availablePropertyKeys={effectiveForcedAvailableFilterKeys ?? editorAvailableFilterKeys}
                  entitySearchTypes={conditionEditorSearchTypes}
                  initialFilters={conditionEditorDraftFilters}
                  disabled={!isEditable}
                  onFiltersChange={(filters) => {
                    setConditionEditorDraftFilters((previous) => {
                      if (getFilterGroupSignature(previous) === getFilterGroupSignature(filters)) {
                        return previous;
                      }
                      return cloneFilterGroup(filters);
                    });
                  }}
                />
              </>
            )}
          </Stack>
          <DialogActions>
            <Button
              variant="secondary"
              onClick={() => {
                if (conditionEditorSlot) {
                  const currentFilters = conditionBuilderRef.current?.getFilters() ?? conditionEditorDraftFilters;
                  const sanitized = sanitizeConditionEditorFiltersForPersistence(currentFilters);
                  onFiltersMapChange(configuredRule.id, conditionEditorSlot.key, sanitized);
                }
                closeConditionEditor();
              }}
            >
              {t_i18n('Done')}
            </Button>
          </DialogActions>
        </Dialog>

        <Dialog
          open={Boolean(confirmAction)}
          onClose={() => setConfirmAction(null)}
          title={confirmAction === 'delete'
            ? t_i18n('Delete rule configuration')
            : confirmAction === 'deactivate'
              ? t_i18n('Deactivate rule configuration')
              : t_i18n('Activate rule configuration')}
        >
          <Typography variant="body2" sx={{ pt: 0.5 }}>
            {confirmActionMessage}
          </Typography>
          <DialogActions>
            <Button variant="secondary" onClick={() => setConfirmAction(null)}>
              {t_i18n('Cancel')}
            </Button>
            <Button
              color={confirmAction === 'activate' ? 'secondary' : 'error'}
              onClick={handleConfirmAction}
            >
              {confirmAction === 'activate' ? t_i18n('Proceed') : t_i18n('Confirm')}
            </Button>
          </DialogActions>
        </Dialog>
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

  const [cardExpanded, setCardExpanded] = useState(true);
  const [configuredRules, setConfiguredRules] = useState<ConfiguredRule[]>([]);
  const [configuredRulesLoaded, setConfiguredRulesLoaded] = useState(false);

  const ruleEntities = useMemo(
    () => buildRuleEntities(rule, schema.schemaRelationsTypesMapping),
    [rule, schema.schemaRelationsTypesMapping],
  );
  const schemaSdoTypes = useMemo(
    () => (schema?.sdos ?? []).map((sdo) => sdo.id),
    [schema?.sdos],
  );
  const schemaScoTypes = useMemo(
    () => (schema?.scos ?? []).map((sco) => sco.id),
    [schema?.scos],
  );
  const ruleTriplets = useMemo(() => buildRuleTriplets(rule), [rule]);
  const defaultFiltersMap = useMemo(() => {
    const initial: Record<string, FilterGroup> = {};
    ruleEntities.forEach((entity) => {
      initial[entity.key] = cloneFilterGroup(entity.initialFilters);
    });
    ruleTriplets.forEach((triplet) => {
      initial[`relationship::${triplet.key}`] = createEmptyFilterGroup();
    });
    return initial;
  }, [ruleEntities, ruleTriplets]);

  const taskWork = task?.work;
  const activeConfiguredRulesCount = configuredRules.filter((r) => r.active).length;
  const totalRuleCount = configuredRules.length > 0 ? configuredRules.length : 1;
  const activeRuleCount = configuredRules.length > 0
    ? activeConfiguredRulesCount
    : (rule.activated ? 1 : 0);

  useEffect(() => {
    if (typeof window === 'undefined') {
      setConfiguredRulesLoaded(true);
      return;
    }
    try {
      const stored = window.localStorage.getItem(RULES_CONFIGURED_LOCAL_STORAGE_KEY);
      const parsed = stored ? JSON.parse(stored) as Record<string, Partial<ConfiguredRule>[]> : {};
      const ruleConfigurations = Array.isArray(parsed?.[rule.id]) ? parsed[rule.id] : [];
      setConfiguredRules(ruleConfigurations.map((configuredRule, index) => {
        const hydrated = hydrateConfiguredRule(rule, configuredRule, defaultFiltersMap);
        return {
          ...hydrated,
          name: hydrated.name || `Configuration ${index + 1}`,
        };
      }));
    } catch {
      setConfiguredRules([]);
    } finally {
      setConfiguredRulesLoaded(true);
    }
  }, [rule.id]);

  useEffect(() => {
    if (!configuredRulesLoaded || typeof window === 'undefined') {
      return;
    }
    try {
      const stored = window.localStorage.getItem(RULES_CONFIGURED_LOCAL_STORAGE_KEY);
      const parsed = stored ? JSON.parse(stored) as Record<string, ConfiguredRule[]> : {};
      parsed[rule.id] = configuredRules;
      window.localStorage.setItem(RULES_CONFIGURED_LOCAL_STORAGE_KEY, JSON.stringify(parsed));
    } catch {
      // Keep UI functional even if local storage is unavailable.
    }
  }, [configuredRules, configuredRulesLoaded, rule.id]);

  useEffect(() => {
    onConfiguredRuleCountsChange?.({
      active: activeRuleCount,
      total: totalRuleCount,
    });
  }, [onConfiguredRuleCountsChange, activeRuleCount, totalRuleCount]);

  const handleAddConfiguredRule = () => {
    // Adding a configured rule takes over activation, so deactivate the parent rule if it was on.
    if (rule.activated) {
      toggle();
    }
    setConfiguredRules((previous) => [
      ...previous,
      {
        id: createId(),
        name: `${t_i18n('Configuration')} ${previous.length + 1}`,
        description: '',
        active: false,
        expanded: true,
        filtersMap: Object.entries(defaultFiltersMap).reduce<Record<string, FilterGroup>>((acc, [key, filterGroup]) => {
          acc[key] = cloneFilterGroup(filterGroup);
          return acc;
        }, {}),
        outputRelationType: defaultOutputRelationType(rule),
        outputConfidenceMode: 'avg',
        outputConfidenceFixed: 50,
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

  const handleConfiguredRuleFiltersMapChange = (
    id: string,
    slotKey: string,
    filters: FilterGroup,
  ) => {
    setConfiguredRules((previous) => {
      let changed = false;
      const next = previous.map((configuredRule) => {
        if (configuredRule.id !== id) {
          return configuredRule;
        }
        const existing = configuredRule.filtersMap[slotKey] ?? createEmptyFilterGroup();
        if (getFilterGroupSignature(existing) === getFilterGroupSignature(filters)) {
          return configuredRule;
        }
        changed = true;
        return {
          ...configuredRule,
          filtersMap: {
            ...configuredRule.filtersMap,
            [slotKey]: cloneFilterGroup(filters),
          },
        };
      });
      return changed ? next : previous;
    });
  };

  const handleDeleteConfiguredRule = (id: string) => {
    if (!id) {
      return;
    }
    setConfiguredRules((previous) => previous.filter((configuredRule) => configuredRule.id !== id));
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
    gap: theme.spacing(2),
    width: '100%',
  };
  const styleIfThenBlock: CSSProperties = {
    flex: 1,
    border: `1px solid ${theme.palette.divider}`,
    borderRadius: Number(theme.shape.borderRadius),
    padding: theme.spacing(1.25),
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'center',
  };
  const styleStep: CSSProperties = {
    margin: theme.spacing(0.75),
    height: 50,
    minWidth: 320,
    display: 'flex',
    alignItems: 'center',
    textAlign: 'center',
    gap: theme.spacing(1),
  };
  const styleProgramTokenTop: CSSProperties = {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    minWidth: 56,
    height: 30,
    padding: `0 ${theme.spacing(1.25)}`,
    borderRadius: Number(theme.shape.borderRadius),
    backgroundColor: 'rgba(0, 0, 0, 0.35)',
    border: `1px solid ${theme.palette.divider}`,
    color: theme.palette.text.primary,
    fontSize: '0.85rem',
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
    flexShrink: 0,
  };

  return (
    <Box sx={{ marginBottom: 3 }}>
      <DangerZoneBlock
        type="rules"
        displayTitle={false}
        title={t_i18n(rule.name)}
        sx={{ title: styleRuleTitle }}
        component={({ disabled, style, title }) => (
          <Card sx={style}>
            {/* ─── Header bar ─────────────────────────────────────────────── */}
            <Box
              sx={{
                display: 'flex',
                alignItems: 'flex-start',
                justifyContent: 'space-between',
                gap: 2,
                flexWrap: 'wrap',
              }}
            >
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5, minWidth: 0, flex: 1 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, flexWrap: 'wrap' }}>
                  {title}
                  {configuredRules.length === 0 ? (
                    <FormGroup sx={{ m: 0 }}>
                      <FormControlLabel
                        sx={{ m: 0 }}
                        label=""
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
                  ) : (
                    <Tooltip title={t_i18n('This rule cannot be activated at the rule level because it has configured rules. Activate the individual configured rules instead.')}>
                      <span style={{ display: 'inline-flex' }}>
                        <FormGroup sx={{ m: 0 }}>
                          <FormControlLabel
                            sx={{ m: 0 }}
                            label=""
                            control={(
                              <Switch
                                color="secondary"
                                disabled
                                checked={false}
                              />
                            )}
                          />
                        </FormGroup>
                      </span>
                    </Tooltip>
                  )}
                  {configuredRules.length > 0 && (
                    <Typography variant="caption" color="text.secondary">
                      {activeConfiguredRulesCount}
                      /
                      {configuredRules.length}
                      {' '}
                      {t_i18n('Configured Rules active')}
                    </Typography>
                  )}
                </Box>
                <Typography variant="body2" color="text.secondary">
                  {t_i18n(rule.description)}
                </Typography>
              </Box>
              {canManageConfiguredRules && (
                <Button
                  size="small"
                  variant="secondary"
                  onClick={handleAddConfiguredRule}
                  startIcon={<AddOutlined fontSize="small" />}
                  style={{ flexShrink: 0 }}
                >
                  {t_i18n('Add configuration')}
                </Button>
              )}
              <Tooltip title={cardExpanded ? t_i18n('Collapse') : t_i18n('Expand')}>
                <IconButton
                  size="small"
                  onClick={() => setCardExpanded((prev) => !prev)}
                  sx={{ flexShrink: 0 }}
                >
                  <ExpandMore
                    fontSize="small"
                    sx={{
                      transform: cardExpanded ? 'rotate(180deg)' : 'rotate(0deg)',
                      transition: (t) => t.transitions.create('transform', { duration: t.transitions.duration.shortest }),
                    }}
                  />
                </IconButton>
              </Tooltip>
            </Box>

            <Collapse in={cardExpanded} timeout="auto" unmountOnExit={false}>
              <Divider sx={{ my: 2 }} />

              {/* ─── Rule definition ────────────────────────────────────────── */}
              <Box sx={{ overflowX: 'auto', minWidth: 0 }}>
                <div style={styleDefinition}>
                  <div style={styleIfThenBlock}>
                    {(rule.display?.if ?? []).map((step, index) => (
                      <div key={index} style={styleStep}>
                        <div style={styleProgramTokenTop}>{t_i18n('IF')}</div>
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
                    <div style={{ ...styleProgramTokenTop, marginTop: theme.spacing(0.5) }}>{t_i18n('THEN')}</div>
                  </div>
                  <div style={styleIfThenBlock}>
                    {(rule.display?.then ?? []).map((step, index) => {
                      return (
                        <div key={index} style={styleStep}>
                          {step?.action && <div style={styleProgramTokenTop}>{step.action}</div>}
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

              {isEngineEnabled && taskWork && (
                <Box sx={{ mt: 2 }}>
                  <RuleListItemProgressBar taskEnable={task.enable ?? false} work={taskWork} />
                </Box>
              )}

              {/* ─── Configured rules ───────────────────────────────────────── */}
              {configuredRules.length > 0 && (
                <>
                  <Divider sx={{ my: 2 }} />
                  <Label>{t_i18n('Configured rules')}</Label>
                  <Stack spacing={1.5} sx={{ mt: 1 }}>
                    {configuredRules.map((configuredRule) => (
                      <AccordionErrorBoundary key={configuredRule.id}>
                        <ConfiguredRuleAccordion
                          configuredRule={configuredRule}
                          rule={rule}
                          ruleEntities={ruleEntities}
                          schemaSdoTypes={schemaSdoTypes}
                          schemaScoTypes={schemaScoTypes}
                          canManage={canManageConfiguredRules}
                          onChange={handleConfiguredRuleChange}
                          onFiltersMapChange={handleConfiguredRuleFiltersMapChange}
                          onToggleExpand={handleConfiguredRuleToggleExpanded}
                          onDelete={handleDeleteConfiguredRule}
                        />
                      </AccordionErrorBoundary>
                    ))}
                  </Stack>
                </>
              )}
            </Collapse>
          </Card>
        )}
      />
    </Box>
  );
};

export default RulesListItem;
