import React, {
  forwardRef,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
} from 'react';
import Box from '@mui/material/Box';
import TextField from '@mui/material/TextField';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import Autocomplete from '@mui/material/Autocomplete';
import Divider from '@mui/material/Divider';
import { DeleteOutline } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import type { Theme } from '../../../../components/Theme';
import { Filter, FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import {
  isNumericFilter,
  useBuildFilterKeysMapFromEntityType,
} from '../../../../utils/filters/filtersUtils';
import useAuth from '../../../../utils/hooks/useAuth';
import { useFormatter } from '../../../../components/i18n';

// ─── Types ───────────────────────────────────────────────────────────────────

interface ConditionRowState {
  id: string;
  key: string;
  operator: string;
  values: string[];
}

export interface RuleConditionBuilderProps {
  slotKind: 'entity' | 'relationship';
  allowedEntityTypes: string[];
  isMultiType: boolean;
  showEntityTypeRow: boolean; // true only for multi-type type-first entity slots
  availablePropertyKeys: string[];
  entitySearchTypes: string[];
  initialFilters: FilterGroup;
  disabled: boolean;
  onFiltersChange: (filters: FilterGroup) => void;
}

export interface RuleConditionBuilderHandle {
  getFilters: () => FilterGroup;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const createRowId = () => `row-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

const OPERATOR_LABELS: Record<string, string> = {
  eq: 'Equals',
  not_eq: 'Not equals',
  gt: 'Greater than',
  gte: '≥',
  lt: 'Less than',
  lte: '≤',
  nil: 'Is empty',
  not_nil: 'Is not empty',
  contains: 'Contains',
  not_contains: "Doesn't contain",
  starts_with: 'Starts with',
  not_starts_with: "Doesn't start with",
  ends_with: 'Ends with',
  not_ends_with: "Doesn't end with",
  search: 'Full text search',
};

const SIMPLE_OPERATORS = ['eq', 'not_eq', 'nil', 'not_nil'];
const NUMERIC_OPERATORS = ['gt', 'gte', 'lt', 'lte', 'eq', 'not_eq'];
const DATE_OPERATORS = ['gt', 'gte', 'lt', 'lte', 'nil', 'not_nil'];

const getSimpleOperatorsForKey = (filterType?: string): string[] => {
  if (filterType === 'date') return DATE_OPERATORS;
  if (isNumericFilter(filterType)) return NUMERIC_OPERATORS;
  if (filterType === 'boolean') return ['eq', 'not_eq'];
  return SIMPLE_OPERATORS;
};

const VALUE_FREE_OPERATORS = new Set(['nil', 'not_nil']);

// ─── Value input ─────────────────────────────────────────────────────────────

interface MarkingOption {
  id: string;
  label: string;
  color?: string | null;
}

interface ConditionValueInputProps {
  filterKey: string;
  filterType?: string;
  operator: string;
  values: string[];
  allowedEntityTypes: string[];
  markingOptions: MarkingOption[];
  disabled: boolean;
  onChange: (values: string[]) => void;
}

const ConditionValueInput = ({
  filterKey,
  filterType,
  operator,
  values,
  allowedEntityTypes,
  markingOptions,
  disabled,
  onChange,
}: ConditionValueInputProps) => {
  const { t_i18n } = useFormatter();

  if (VALUE_FREE_OPERATORS.has(operator)) {
    return null;
  }

  // Marking select
  if (filterKey === 'objectMarking') {
    const selectedOptions = markingOptions.filter((opt) => values.includes(opt.id));
    return (
      <Autocomplete
        multiple
        size="small"
        disabled={disabled}
        options={markingOptions}
        getOptionLabel={(opt) => opt.label}
        value={selectedOptions}
        onChange={(_, selected) => onChange(selected.map((opt) => opt.id))}
        renderTags={(tagValues, getTagProps) => tagValues.map((opt, index) => {
          const tagProps = getTagProps({ index });
          return (
            <Chip
              {...tagProps}
              key={opt.id}
              label={opt.label}
              size="small"
                sx={{
                maxWidth: 120,
                backgroundColor: opt.color ?? undefined,
                color: opt.color ? '#fff' : undefined,
                fontSize: '0.65rem',
              }}
            />
          );
        })}
        renderInput={(params) => <TextField {...params} size="small" placeholder={values.length === 0 ? t_i18n('Select marking...') : ''} />}
        sx={{ flex: 1 }}
      />
    );
  }

  // Entity type select
  if (filterKey === 'entity_type') {
    const selectedOptions = allowedEntityTypes.filter((t) => values.includes(t));
    return (
      <Autocomplete
        multiple
        size="small"
        disabled={disabled}
        options={allowedEntityTypes}
        value={selectedOptions}
        onChange={(_, selected) => onChange(selected)}
        renderTags={(tagValues, getTagProps) => tagValues.map((opt, index) => {
          const tagProps = getTagProps({ index });
          return <Chip {...tagProps} key={opt} label={opt} size="small" sx={{ fontSize: '0.65rem' }} />;
        })}
        renderInput={(params) => <TextField {...params} size="small" placeholder={t_i18n('Any')} />}
        sx={{ flex: 1 }}
      />
    );
  }

  // Boolean select
  if (filterType === 'boolean') {
    return (
      <TextField
        select
        size="small"
        disabled={disabled}
        value={values[0] ?? ''}
        onChange={(e) => onChange([e.target.value])}
        sx={{ flex: 1 }}
      >
        <MenuItem value="true">{t_i18n('True')}</MenuItem>
        <MenuItem value="false">{t_i18n('False')}</MenuItem>
      </TextField>
    );
  }

  // Numeric input
  if (isNumericFilter(filterType)) {
    return (
      <TextField
        type="number"
        size="small"
        disabled={disabled}
        value={values[0] ?? ''}
        onChange={(e) => onChange([e.target.value])}
        sx={{ flex: 1 }}
        inputProps={{ min: 0, max: filterKey === 'confidence' ? 100 : undefined }}
      />
    );
  }

  // Date input
  if (filterType === 'date') {
    return (
      <TextField
        type="date"
        size="small"
        disabled={disabled}
        value={values[0] ?? ''}
        onChange={(e) => onChange([e.target.value])}
        sx={{ flex: 1 }}
        InputLabelProps={{ shrink: true }}
      />
    );
  }

  // Default: text input
  return (
    <TextField
      size="small"
      disabled={disabled}
      value={values[0] ?? ''}
      onChange={(e) => onChange([e.target.value])}
      sx={{ flex: 1 }}
      placeholder={t_i18n('Value...')}
    />
  );
};

// ─── Main component ───────────────────────────────────────────────────────────

const RuleConditionBuilder = forwardRef<RuleConditionBuilderHandle, RuleConditionBuilderProps>(({
  slotKind,
  allowedEntityTypes,
  isMultiType,
  showEntityTypeRow,
  availablePropertyKeys,
  entitySearchTypes,
  initialFilters,
  disabled,
  onFiltersChange,
}, ref) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { me } = useAuth();

  const markingOptions = useMemo<MarkingOption[]>(() => (
    (me.allowed_marking ?? []).map((m) => ({
      id: m.id,
      label: m.definition ?? m.id,
      color: m.x_opencti_color,
    }))
  ), [me.allowed_marking]);

  // ─── Parse initial filters ────────────────────────────────────────────────

  const parseInitialFilters = (filters: FilterGroup): { entityTypeValues: string[]; rows: ConditionRowState[] } => {
    const entityTypeValues: string[] = [];
    const rows: ConditionRowState[] = [];
    (filters.filters ?? []).forEach((filter) => {
      const safeValues = (filter.values ?? []).filter((value): value is string => typeof value === 'string');
      if (filter.key === 'entity_type') {
        entityTypeValues.push(...safeValues);
      } else {
        rows.push({
          id: createRowId(),
          key: filter.key,
          operator: filter.operator ?? 'eq',
          values: safeValues,
        });
      }
    });
    return { entityTypeValues, rows };
  };

  const initial = useMemo(() => parseInitialFilters(initialFilters), []);
  const [entityTypeValues, setEntityTypeValues] = useState<string[]>(initial.entityTypeValues);
  const [propertyRows, setPropertyRows] = useState<ConditionRowState[]>(initial.rows);
  const lastEmittedSignatureRef = useRef<string>('');

  const effectiveScopeEntityTypes = useMemo(() => {
    if (!showEntityTypeRow) {
      return entitySearchTypes;
    }
    if (entityTypeValues.length > 0) {
      return entityTypeValues;
    }
    return allowedEntityTypes;
  }, [showEntityTypeRow, entitySearchTypes, entityTypeValues, allowedEntityTypes]);

  const filterKeysMap = useBuildFilterKeysMapFromEntityType(
    effectiveScopeEntityTypes,
    {
      mode: showEntityTypeRow ? 'intersection' : 'union',
    },
  );

  const effectiveAvailablePropertyKeys = useMemo(() => {
    const allowedKeys = new Set(availablePropertyKeys);
    return Array.from(filterKeysMap.keys()).filter((key) => allowedKeys.has(key));
  }, [filterKeysMap, availablePropertyKeys]);

  useEffect(() => {
    setPropertyRows((prev) => {
      if (effectiveAvailablePropertyKeys.length === 0) {
        return [];
      }
      const allowedKeys = new Set(effectiveAvailablePropertyKeys);
      let hasChange = false;
      const nextRows = prev
        .map((row) => {
          if (allowedKeys.has(row.key)) {
            return row;
          }
          hasChange = true;
          const fallbackKey = effectiveAvailablePropertyKeys[0];
          const filterDef = filterKeysMap.get(fallbackKey);
          const fallbackOperator = getSimpleOperatorsForKey(filterDef?.type)[0] ?? 'eq';
          return {
            ...row,
            key: fallbackKey,
            operator: fallbackOperator,
            values: [],
          };
        })
        .filter((row) => {
          const keep = allowedKeys.has(row.key);
          if (!keep) {
            hasChange = true;
          }
          return keep;
        });
      return hasChange ? nextRows : prev;
    });
  }, [effectiveAvailablePropertyKeys, filterKeysMap]);

  const serializeCurrentFilters = (): FilterGroup => {
    const filters: Filter[] = [];
    if (showEntityTypeRow && entityTypeValues.length > 0) {
      filters.push({ key: 'entity_type', values: entityTypeValues, operator: 'eq', mode: 'or' });
    }
    propertyRows.forEach((row) => {
      if (row.key && (VALUE_FREE_OPERATORS.has(row.operator) || row.values.length > 0)) {
        filters.push({ key: row.key, values: row.values, operator: row.operator, mode: 'or' });
      }
    });
    return { mode: 'and', filters, filterGroups: [] };
  };

  useImperativeHandle(ref, () => ({
    getFilters: () => serializeCurrentFilters(),
  }), [entityTypeValues, propertyRows, showEntityTypeRow]);

  // ─── Serialize to FilterGroup ─────────────────────────────────────────────

  useEffect(() => {
    const nextFilterGroup = serializeCurrentFilters();
    const nextSignature = JSON.stringify(nextFilterGroup);
    if (nextSignature === lastEmittedSignatureRef.current) {
      return;
    }
    lastEmittedSignatureRef.current = nextSignature;
    onFiltersChange(nextFilterGroup);
  }, [entityTypeValues, propertyRows, showEntityTypeRow, onFiltersChange]);

  // ─── Row helpers ──────────────────────────────────────────────────────────

  const addRow = () => {
    const firstKey = effectiveAvailablePropertyKeys[0];
    if (!firstKey) return;
    const filterDef = filterKeysMap.get(firstKey);
    const operators = getSimpleOperatorsForKey(filterDef?.type);
    setPropertyRows((prev) => [
      ...prev,
      { id: createRowId(), key: firstKey, operator: operators[0] ?? 'eq', values: [] },
    ]);
  };

  const updateRowKey = (id: string, key: string) => {
    const filterDef = filterKeysMap.get(key);
    const operators = getSimpleOperatorsForKey(filterDef?.type);
    setPropertyRows((prev) => prev.map((row) => (
      row.id === id ? { ...row, key, operator: operators[0] ?? 'eq', values: [] } : row
    )));
  };

  const updateRowOperator = (id: string, operator: string) => {
    setPropertyRows((prev) => prev.map((row) => (
      row.id === id ? { ...row, operator, values: VALUE_FREE_OPERATORS.has(operator) ? [] : row.values } : row
    )));
  };

  const updateRowValues = (id: string, values: string[]) => {
    setPropertyRows((prev) => prev.map((row) => (
      row.id === id ? { ...row, values } : row
    )));
  };

  const deleteRow = (id: string) => {
    setPropertyRows((prev) => prev.filter((row) => row.id !== id));
  };

  // ─── Render ───────────────────────────────────────────────────────────────

  // Grid: [And connector | Property col | Operator col | Value col | Delete]
  // The And connector and Delete columns are fixed; the 3 data columns are equal
  const colTemplate = '48px 1fr 160px 1fr 44px';

  // Helper: renders a labelled field cell (label above, field below)
  const renderLabelledCell = (label: string, children: React.ReactNode) => (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.25 }}>
      <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.68rem', lineHeight: 1 }}>
        {label}
      </Typography>
      {children}
    </Box>
  );

  const renderEntityTypeRow = () => (
    <Box sx={{ display: 'grid', gridTemplateColumns: colTemplate, columnGap: 1, alignItems: 'end' }}>
      {/* Spacer for And column */}
      <Box />

      {/* "Entity Type" grey label box — spans the Property column */}
      <Box sx={{
        height: 40,
        display: 'flex',
        alignItems: 'center',
        px: 1.5,
        borderRadius: 1,
        border: (t) => `1px solid ${t.palette.divider}`,
        background: (t) => t.palette.action.selected,
        mt: 'auto',
      }}>
        <Typography variant="body2" sx={{ fontWeight: 600 }}>{t_i18n('Entity Type')}</Typography>
      </Box>

      {/* Operator column with label */}
      {renderLabelledCell(t_i18n('Operator'), (
        <TextField
          select
          size="small"
          disabled
          value="eq"
        >
          <MenuItem value="eq">{t_i18n('Equals')}</MenuItem>
        </TextField>
      ))}

      {/* Value column with label */}
      {renderLabelledCell(t_i18n('Entity type'), (
        <Autocomplete
          multiple
          size="small"
          disabled={disabled}
          options={allowedEntityTypes}
          value={allowedEntityTypes.filter((t) => entityTypeValues.includes(t))}
          onChange={(_, selected) => setEntityTypeValues(selected)}
          renderTags={(tagValues, getTagProps) => tagValues.map((opt, index) => {
            const tagProps = getTagProps({ index });
            return <Chip {...tagProps} key={opt} label={opt} size="small" sx={{ fontSize: '0.65rem' }} />;
          })}
          renderInput={(params) => (
            <TextField
              {...params}
              size="small"
              placeholder={entityTypeValues.length === 0 ? t_i18n('Any') : ''}
            />
          )}
        />
      ))}

      {/* Spacer for delete column */}
      <Box />
    </Box>
  );

  const renderPropertyRow = (row: ConditionRowState, index: number) => {
    const filterDef = filterKeysMap.get(row.key);
    const operators = getSimpleOperatorsForKey(filterDef?.type).filter((op) => OPERATOR_LABELS[op]);

    return (
      <Box key={row.id} sx={{ display: 'grid', gridTemplateColumns: colTemplate, columnGap: 1, alignItems: 'end' }}>
        {/* And connector */}
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', pb: 0.5 }}>
          {index > 0 && (
            <Typography variant="body2" sx={{ color: 'text.primary', fontWeight: 600 }}>
              {t_i18n('And')}
            </Typography>
          )}
        </Box>

        {/* Property select with label */}
        {renderLabelledCell(t_i18n('Property'), (
          <TextField
            select
            size="small"
            disabled={disabled}
            value={row.key}
            onChange={(e) => updateRowKey(row.id, e.target.value)}
          >
            {effectiveAvailablePropertyKeys.map((key) => {
              const def = filterKeysMap.get(key);
              return (
                <MenuItem key={key} value={key}>
                  {def?.label ?? key}
                </MenuItem>
              );
            })}
          </TextField>
        ))}

        {/* Operator select with label */}
        {renderLabelledCell(t_i18n('Operator'), (
          <TextField
            select
            size="small"
            disabled={disabled}
            value={operators.includes(row.operator) ? row.operator : operators[0] ?? 'eq'}
            onChange={(e) => updateRowOperator(row.id, e.target.value)}
          >
            {operators.map((op) => (
              <MenuItem key={op} value={op}>
                {t_i18n(OPERATOR_LABELS[op] ?? op)}
              </MenuItem>
            ))}
          </TextField>
          ))}

        {/* Value input with label */}
        {renderLabelledCell(t_i18n('Value'), (
          <ConditionValueInput
            filterKey={row.key}
            filterType={filterDef?.type}
            operator={row.operator}
            values={row.values}
            allowedEntityTypes={allowedEntityTypes}
            markingOptions={markingOptions}
            disabled={disabled}
            onChange={(values) => updateRowValues(row.id, values)}
          />
        ))}

        {/* Delete */}
        <IconButton
          size="small"
          disabled={disabled}
          onClick={() => deleteRow(row.id)}
          sx={{
            width: 36,
            height: 36,
            mb: 0.25,
            borderRadius: 1,
            color: 'error.main',
            '&:hover': { backgroundColor: 'action.hover' },
          }}
        >
          <DeleteOutline sx={{ fontSize: 18 }} />
        </IconButton>
      </Box>
    );
  };

  const hasAnyContent = showEntityTypeRow || propertyRows.length > 0;

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.25 }}>
      {/* Entity type row */}
      {showEntityTypeRow && renderEntityTypeRow()}

      {/* Divider between entity type row and property rows */}
      {showEntityTypeRow && (propertyRows.length > 0 || !disabled) && (
        <Divider sx={{ my: 0.5 }} />
      )}

      {/* Property condition rows */}
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.25 }}>
        {propertyRows.map((row, index) => renderPropertyRow(row, index))}
      </Box>

      {/* Empty state */}
      {!hasAnyContent && (
        <Typography variant="caption" color="text.secondary" sx={{ textAlign: 'center', py: 1 }}>
          {t_i18n('No conditions set. Add a property condition below.')}
        </Typography>
      )}

      {/* Add property condition */}
      {!disabled && effectiveAvailablePropertyKeys.length > 0 && (
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 0.5 }}>
          <Button
            variant="secondary"
            size="small"
            onClick={addRow}
            sx={{ color: theme.palette.primary.main, textTransform: 'none', fontWeight: 500 }}
          >
            {t_i18n('Add property condition')}
          </Button>
        </Box>
      )}
    </Box>
  );
});

export default RuleConditionBuilder;
