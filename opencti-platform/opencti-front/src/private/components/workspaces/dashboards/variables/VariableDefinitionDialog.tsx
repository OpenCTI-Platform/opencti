import React, { useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import MUIAutocomplete from '@mui/material/Autocomplete';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import MenuItem from '@mui/material/MenuItem';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import MUITextField from '@mui/material/TextField';
import { useFormik } from 'formik';
import DatePicker from '@common/input/DatePicker';
import Filters from '@components/common/lists/Filters';
import FilterIconButton from '../../../../../components/FilterIconButton';
import EntitySelectWithTypes from '../../../../../components/fields/EntitySelectWithTypes';
import { useFormatter } from '../../../../../components/i18n';
import { fetchQuery } from '../../../../../relay/environment';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import useVocabularyCategory from '../../../../../utils/hooks/useVocabularyCategory';
import useFiltersState from '../../../../../utils/filters/useFiltersState';
import { isFilterGroupNotEmpty, serializeFilterGroupForBackend, useAvailableFilterKeysForEntityTypes } from '../../../../../utils/filters/filtersUtils';
import { killChainPhasesSearchQuery } from '../../../settings/KillChainPhases';
import { vocabularySearchQuery } from '../../../settings/VocabularyQuery';
import { getNodes } from '../../../../../utils/connection';
import { KillChainPhasesSearchQuery$data } from '../../../settings/__generated__/KillChainPhasesSearchQuery.graphql';
import { labelsSearchQuery } from '../../../settings/LabelsQuery';
import { markingDefinitionsLinesSearchQuery } from '../../../settings/MarkingDefinitionsQuery';
import { identitySearchCreatorsSearchQuery } from '../../../common/identities/IdentitySearch';
import { statusFieldStatusesSearchQuery } from '../../../common/form/StatusField';
import { parse } from '../../../../../utils/Time';
import type { EntityValue } from '../../../../../utils/filters/useSearchEntities';

const variableAddMutation = graphql`
  mutation VariableDefinitionDialogAddMutation($id: ID!, $input: DashboardVariableInput!) {
    workspaceVariableAdd(id: $id, input: $input) {
      id
      manifest
      variables {
        id
        name
        filterKey
        filterKeyType
        defaultValue
        restrictionMode
        restrictionValues
        restrictionFilters
      }
    }
  }
`;

const groupsSearchQuery = graphql`
  query VariableDefinitionDialogGroupsSearchQuery($search: String) {
    groups(search: $search, first: 50) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const entityRestrictionSearchQuery = graphql`
  query VariableDefinitionDialogEntityRestrictionSearchQuery($filters: FilterGroup, $search: String, $count: Int) {
    stixCoreObjects(filters: $filters, search: $search, first: $count) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
        }
      }
    }
  }
`;

type FilterKeyType = 'entity_ref' | 'vocabulary' | 'kill_chain' | 'boolean' | 'numeric' | 'text' | 'label' | 'user' | 'marking' | 'status' | 'date' | 'group';

const FILTER_KEY_TYPES: Array<{ value: FilterKeyType; label: string }> = [
  { value: 'entity_ref', label: 'Entity selector' },
  { value: 'vocabulary', label: 'Vocabulary' },
  { value: 'kill_chain', label: 'Kill chain phase' },
  { value: 'boolean', label: 'Boolean' },
  { value: 'numeric', label: 'Numeric' },
  { value: 'text', label: 'Text' },
  { value: 'label', label: 'Label selector' },
  { value: 'user', label: 'User selector' },
  { value: 'marking', label: 'Marking selector' },
  { value: 'status', label: 'Status' },
  { value: 'date', label: 'Date' },
  { value: 'group', label: 'Group selector' },
];

// Types for which a "restriction" (limiting the selectable options) can be configured at creation time
const RESTRICTABLE_TYPES: FilterKeyType[] = ['entity_ref', 'vocabulary', 'kill_chain', 'label', 'user', 'marking', 'status', 'group'];

interface KillChainOption {
  label: string;
  value: string;
  kill_chain_name: string;
  phase_name: string;
}

interface VocabOption {
  label: string;
  value: string;
}

interface SimpleOption {
  label: string;
  value: string;
  color?: string;
}

/** Generic restriction mode picker (semantics of the options depend on the variable type). */
const RestrictionModeSelect: React.FC<{
  value: string;
  onChange: (value: string) => void;
  options: Array<{ value: string; label: string }>;
}> = ({ value, onChange, options }) => {
  const { t_i18n } = useFormatter();
  return (
    <FormControl fullWidth margin="normal">
      <InputLabel>{t_i18n('Restriction')}</InputLabel>
      <Select value={value} label={t_i18n('Restriction')} onChange={(e) => onChange(e.target.value)}>
        {options.map((option) => (
          <MenuItem key={option.value} value={option.value}>{t_i18n(option.label)}</MenuItem>
        ))}
      </Select>
    </FormControl>
  );
};

/** Generic multi-select used to define the "allowed values" of a restricted variable. */
const SimpleMultiSelect: React.FC<{
  options: SimpleOption[];
  value: SimpleOption[];
  onChange: (value: SimpleOption[]) => void;
  label: string;
  onOpen?: () => void;
}> = ({ options, value, onChange, label, onOpen }) => (
  <MUIAutocomplete
    multiple
    sx={{ mt: 2 }}
    options={options}
    getOptionLabel={(o) => o.label}
    isOptionEqualToValue={(o, v) => o.value === v.value}
    value={value}
    onOpen={onOpen}
    onFocus={onOpen}
    onChange={(_, val) => onChange(val)}
    renderInput={(params) => (
      <MUITextField {...params} label={label} fullWidth />
    )}
  />
);

interface VariableDefinitionDialogProps {
  open: boolean;
  workspaceId: string;
  onClose: () => void;
}

const VariableDefinitionDialog: React.FC<VariableDefinitionDialogProps> = ({
  open,
  workspaceId,
  onClose,
}) => {
  const { t_i18n } = useFormatter();
  const [commitAdd] = useApiMutation(variableAddMutation);
  const { categoriesOptions } = useVocabularyCategory();
  const entityFilterKeys = useAvailableFilterKeysForEntityTypes(['Stix-Core-Object']);

  // Shared restriction mode, semantics depend on the selected variable type
  const [restrictionMode, setRestrictionMode] = useState<string>('none');

  // Entity ref state
  const [entityValue, setEntityValue] = useState<EntityValue | null>(null);
  const [entityFilters, entityFilterHelpers] = useFiltersState();
  const [filteredEntityOptions, setFilteredEntityOptions] = useState<EntityValue[]>([]);
  const [manualEntities, setManualEntities] = useState<EntityValue[]>([]);

  // Vocabulary state
  const [vocabCategory, setVocabCategory] = useState<string>('');
  const [vocabOptions, setVocabOptions] = useState<VocabOption[]>([]);
  const [vocabValue, setVocabValue] = useState<VocabOption | null>(null);
  const [vocabRestricted, setVocabRestricted] = useState<VocabOption[]>([]);

  // Kill chain state
  const [killChainOptions, setKillChainOptions] = useState<KillChainOption[]>([]);
  const [killChainNameValue, setKillChainNameValue] = useState<string>('');
  const [killChainValue, setKillChainValue] = useState<KillChainOption | null>(null);
  const [killChainRestricted, setKillChainRestricted] = useState<KillChainOption[]>([]);

  // Label state
  const [labelOptions, setLabelOptions] = useState<SimpleOption[]>([]);
  const [labelValue, setLabelValue] = useState<SimpleOption | null>(null);
  const [labelRestricted, setLabelRestricted] = useState<SimpleOption[]>([]);

  // User state
  const [userOptions, setUserOptions] = useState<SimpleOption[]>([]);
  const [userValue, setUserValue] = useState<SimpleOption | null>(null);
  const [userRestricted, setUserRestricted] = useState<SimpleOption[]>([]);

  // Marking state
  const [markingOptions, setMarkingOptions] = useState<SimpleOption[]>([]);
  const [markingValue, setMarkingValue] = useState<SimpleOption | null>(null);
  const [markingRestricted, setMarkingRestricted] = useState<SimpleOption[]>([]);

  // Status state
  const [statusOptions, setStatusOptions] = useState<SimpleOption[]>([]);
  const [statusValue, setStatusValue] = useState<SimpleOption | null>(null);
  const [statusRestricted, setStatusRestricted] = useState<SimpleOption[]>([]);

  // Group state
  const [groupOptions, setGroupOptions] = useState<SimpleOption[]>([]);
  const [groupValue, setGroupValue] = useState<SimpleOption | null>(null);
  const [groupRestricted, setGroupRestricted] = useState<SimpleOption[]>([]);

  // Date state
  const [dateValue, setDateValue] = useState<Date | null>(null);

  const resetExtraState = () => {
    setRestrictionMode('none');
    setEntityValue(null);
    entityFilterHelpers.handleClearAllFilters?.();
    setFilteredEntityOptions([]);
    setManualEntities([]);
    setVocabCategory('');
    setVocabOptions([]);
    setVocabValue(null);
    setVocabRestricted([]);
    setKillChainOptions([]);
    setKillChainNameValue('');
    setKillChainValue(null);
    setKillChainRestricted([]);
    setLabelOptions([]);
    setLabelValue(null);
    setLabelRestricted([]);
    setUserOptions([]);
    setUserValue(null);
    setUserRestricted([]);
    setMarkingOptions([]);
    setMarkingValue(null);
    setMarkingRestricted([]);
    setStatusOptions([]);
    setStatusValue(null);
    setStatusRestricted([]);
    setGroupOptions([]);
    setGroupValue(null);
    setGroupRestricted([]);
    setDateValue(null);
  };

  const handleVocabCategoryChange = (category: string) => {
    setVocabCategory(category);
    setVocabValue(null);
    setVocabRestricted([]);
    if (!category) return;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    fetchQuery(vocabularySearchQuery, { category }).toPromise().then((data: any) => {
      const opts: VocabOption[] = (data?.vocabularies?.edges ?? []).map((e: any) => ({
        label: e.node.name,
        value: e.node.name,
      }));
      setVocabOptions(opts);
    });
  };

  const searchKillChains = (search = '') => {
    fetchQuery(killChainPhasesSearchQuery, { search })
      .toPromise()
      .then((data) => {
        const dataNodes = getNodes((data as KillChainPhasesSearchQuery$data).killChainPhases);
        dataNodes.sort((a, b) => (a.x_opencti_order ?? 0) - (b.x_opencti_order ?? 0));
        const phases: KillChainOption[] = dataNodes.map((node) => ({
          label: `[${node.kill_chain_name}] ${node.phase_name}`,
          value: node.id,
          kill_chain_name: node.kill_chain_name,
          phase_name: node.phase_name,
        }));
        setKillChainOptions(phases);
      })
      .catch(() => {
        setKillChainOptions([]);
      });
  };

  const killChainNames = Array.from(new Set(killChainOptions.map((o) => o.kill_chain_name))).sort();
  const killChainPhasesForName = killChainOptions.filter((o) => o.kill_chain_name === killChainNameValue);

  const searchLabels = (search = '') => {
    fetchQuery(labelsSearchQuery, { search }).toPromise().then((data: any) => {
      const opts: SimpleOption[] = (data?.labels?.edges ?? []).map((e: any) => ({
        label: e.node.value,
        value: e.node.id,
        color: e.node.color,
      }));
      setLabelOptions(opts);
    });
  };

  const searchUsers = (search = '') => {
    fetchQuery(identitySearchCreatorsSearchQuery, { entityTypes: ['User'] }).toPromise().then((data: any) => {
      const opts: SimpleOption[] = (data?.creators?.edges ?? [])
        .map((e: any) => ({ label: e.node.name, value: e.node.id }))
        .filter((o: SimpleOption) => o.label.toLowerCase().includes(search.toLowerCase()));
      setUserOptions(opts);
    });
  };

  const searchMarkings = (search = '') => {
    fetchQuery(markingDefinitionsLinesSearchQuery, { search }).toPromise().then((data: any) => {
      const opts: SimpleOption[] = (data?.markingDefinitions?.edges ?? []).map((e: any) => ({
        label: e.node.definition,
        value: e.node.id,
        color: e.node.x_opencti_color,
      }));
      setMarkingOptions(opts);
    });
  };

  const searchStatuses = (search = '') => {
    fetchQuery(statusFieldStatusesSearchQuery, {
      first: 100,
      filters: null,
      orderBy: 'order',
      orderMode: 'asc',
      search,
    }).toPromise().then((data: any) => {
      const opts: SimpleOption[] = (data?.statuses?.edges ?? [])
        .filter((e: any) => e?.node?.template)
        .map((e: any) => ({
          label: `${e.node.template.name} (${e.node.type})`,
          value: e.node.id,
          color: e.node.template.color,
        }));
      setStatusOptions(opts);
    });
  };

  const searchGroups = (search = '') => {
    fetchQuery(groupsSearchQuery, { search }).toPromise().then((data: any) => {
      const opts: SimpleOption[] = (data?.groups?.edges ?? []).map((e: any) => ({
        label: e.node.name,
        value: e.node.id,
      }));
      setGroupOptions(opts);
    });
  };

  const searchFilteredEntities = (search = '') => {
    fetchQuery(entityRestrictionSearchQuery, {
      filters: isFilterGroupNotEmpty(entityFilters) ? JSON.parse(serializeFilterGroupForBackend(entityFilters)) : null,
      search,
      count: 50,
    }).toPromise().then((data: any) => {
      const opts: EntityValue[] = (data?.stixCoreObjects?.edges ?? []).map((e: any) => ({
        label: e.node.representative?.main ?? e.node.id,
        value: e.node.id,
        type: e.node.entity_type,
      }));
      setFilteredEntityOptions(opts);
    });
  };

  const asStringOrNull = (value: unknown): string | null => {
    if (value === null || value === undefined || value === '') {
      return null;
    }
    return String(value);
  };

  const getDefaultValue = (filterKeyType: FilterKeyType, simpleDefault: string): string | null => {
    switch (filterKeyType) {
      case 'entity_ref':
        return restrictionMode === 'filter'
          ? asStringOrNull(filteredEntityOptions.find((o) => o.value === entityValue?.value)?.value)
          : asStringOrNull(entityValue?.value);
      case 'vocabulary': return asStringOrNull(vocabValue?.value);
      case 'kill_chain': return asStringOrNull(killChainValue?.value);
      case 'label': return asStringOrNull(labelValue?.value);
      case 'user': return asStringOrNull(userValue?.value);
      case 'marking': return asStringOrNull(markingValue?.value);
      case 'status': return asStringOrNull(statusValue?.value);
      case 'group': return asStringOrNull(groupValue?.value);
      case 'boolean': return 'false';
      case 'date': return dateValue ? parse(dateValue).format() : null;
      default: return asStringOrNull(simpleDefault);
    }
  };

  const getRestrictionMode = (filterKeyType: FilterKeyType): string | null => {
    if (!RESTRICTABLE_TYPES.includes(filterKeyType) || restrictionMode === 'none') return null;
    return restrictionMode;
  };

  const getRestrictionValues = (filterKeyType: FilterKeyType): string[] | null => {
    switch (filterKeyType) {
      case 'entity_ref':
        return restrictionMode === 'manual'
          ? manualEntities.map((e) => e.value).filter((v): v is string => !!v)
          : null;
      case 'vocabulary': return restrictionMode === 'restricted' ? vocabRestricted.map((o) => o.value) : null;
      case 'kill_chain': return restrictionMode === 'restricted' ? killChainRestricted.map((o) => o.value) : null;
      case 'label': return restrictionMode === 'restricted' ? labelRestricted.map((o) => o.value) : null;
      case 'user': return restrictionMode === 'restricted' ? userRestricted.map((o) => o.value) : null;
      case 'marking': return restrictionMode === 'restricted' ? markingRestricted.map((o) => o.value) : null;
      case 'status': return restrictionMode === 'restricted' ? statusRestricted.map((o) => o.value) : null;
      case 'group': return restrictionMode === 'restricted' ? groupRestricted.map((o) => o.value) : null;
      default: return null;
    }
  };

  const getRestrictionFilters = (filterKeyType: FilterKeyType): string | null => {
    if (filterKeyType === 'entity_ref' && restrictionMode === 'filter' && isFilterGroupNotEmpty(entityFilters)) {
      return serializeFilterGroupForBackend(entityFilters);
    }
    return null;
  };

  const formik = useFormik({
    initialValues: {
      name: '',
      filterKeyType: 'entity_ref' as FilterKeyType,
      defaultValue: '',
    },
    validate: (values) => {
      const errors: Record<string, string> = {};
      if (!values.name.trim()) errors.name = t_i18n('Name is required');
      return errors;
    },
    onSubmit: (values, { resetForm }) => {
      commitAdd({
        variables: {
          id: workspaceId,
          input: {
            name: values.name,
            filterKey: (() => {
              if (values.filterKeyType === 'vocabulary') return vocabCategory || 'vocabulary';
              if (values.filterKeyType === 'kill_chain') return killChainNameValue || 'kill_chain';
              return values.filterKeyType;
            })(),
            filterKeyType: values.filterKeyType,
            defaultValue: getDefaultValue(values.filterKeyType, values.defaultValue),
            restrictionMode: getRestrictionMode(values.filterKeyType),
            restrictionValues: getRestrictionValues(values.filterKeyType),
            restrictionFilters: getRestrictionFilters(values.filterKeyType),
          },
        },
        onCompleted: () => {
          resetForm();
          resetExtraState();
          onClose();
        },
      });
    },
  });

  const handleClose = () => {
    formik.resetForm();
    resetExtraState();
    onClose();
  };

  const handleTypeChange = (e: SelectChangeEvent<string>) => {
    formik.setFieldValue('filterKeyType', e.target.value as FilterKeyType);
    formik.setFieldValue('defaultValue', '');
    resetExtraState();
  };

  const fkt = formik.values.filterKeyType;

  useEffect(() => {
    if (fkt === 'kill_chain' && killChainOptions.length === 0) {
      searchKillChains('');
    }
  }, [fkt]);

  const canSubmit = !!formik.values.name.trim()
    && !(fkt === 'vocabulary' && !vocabCategory)
    && !(fkt === 'kill_chain' && !killChainNameValue);

  return (
    <Dialog open={open} onClose={handleClose} fullWidth maxWidth="sm">
      <form onSubmit={formik.handleSubmit}>
        <DialogTitle>{t_i18n('Add dashboard variable')}</DialogTitle>
        <DialogContent>

          {/* Name */}
          <MUITextField
            fullWidth
            margin="normal"
            label={t_i18n('Variable name')}
            name="name"
            value={formik.values.name}
            onChange={formik.handleChange}
            error={!!formik.errors.name && formik.touched.name}
            helperText={formik.touched.name && formik.errors.name}
          />

          {/* Type */}
          <FormControl fullWidth margin="normal">
            <InputLabel>{t_i18n('Type')}</InputLabel>
            <Select
              value={formik.values.filterKeyType}
              onChange={handleTypeChange}
              label={t_i18n('Type')}
            >
              {FILTER_KEY_TYPES.map((type) => (
                <MenuItem key={type.value} value={type.value}>
                  {t_i18n(type.label)}
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {/* ── Entity selector ── */}
          {fkt === 'entity_ref' && (
            <>
              <RestrictionModeSelect
                value={restrictionMode}
                onChange={setRestrictionMode}
                options={[
                  { value: 'none', label: 'No restriction' },
                  { value: 'filter', label: 'Restrict via filters' },
                  { value: 'manual', label: 'Manually select entities' },
                ]}
              />

              {restrictionMode === 'none' && (
                <Box sx={{ mt: 2 }}>
                  <EntitySelectWithTypes
                    label={t_i18n('Default entity (optional)')}
                    value={entityValue}
                    handleChange={(val) => setEntityValue(val)}
                    entitiesToExclude={[]}
                  />
                </Box>
              )}

              {restrictionMode === 'filter' && (
                <>
                  <Box sx={{ mt: 2, display: 'flex', alignItems: 'center' }}>
                    <Filters
                      availableFilterKeys={entityFilterKeys}
                      helpers={entityFilterHelpers}
                      searchContext={{ entityTypes: ['Stix-Core-Object'] }}
                    />
                  </Box>
                  <Box sx={{ mt: 1 }}>
                    <FilterIconButton
                      filters={entityFilters}
                      helpers={entityFilterHelpers}
                      searchContext={{ entityTypes: ['Stix-Core-Object'] }}
                    />
                  </Box>
                  <MUIAutocomplete
                    sx={{ mt: 2 }}
                    options={filteredEntityOptions}
                    getOptionLabel={(o) => o.label}
                    value={entityValue}
                    filterOptions={(x) => x}
                    onOpen={() => searchFilteredEntities('')}
                    onFocus={() => searchFilteredEntities('')}
                    onInputChange={(_, val, reason) => {
                      if (reason === 'input' || reason === 'clear') {
                        searchFilteredEntities(val);
                      }
                    }}
                    onChange={(_, val) => setEntityValue(val as EntityValue | null)}
                    renderInput={(params) => (
                      <MUITextField {...params} label={t_i18n('Default entity (optional, must match filters)')} fullWidth />
                    )}
                  />
                </>
              )}

              {restrictionMode === 'manual' && (
                <>
                  <Box sx={{ mt: 2 }}>
                    <EntitySelectWithTypes
                      label={t_i18n('Add an entity')}
                      value={null}
                      handleChange={(val) => setManualEntities((prev) => (
                        prev.some((e) => e.value === val.value) ? prev : [...prev, val]
                      ))}
                      entitiesToExclude={manualEntities.map((e) => e.value ?? '')}
                    />
                  </Box>
                  <Box sx={{ mt: 1, display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                    {manualEntities.map((entity) => (
                      <Chip
                        key={entity.value}
                        label={entity.label}
                        size="small"
                        onDelete={() => setManualEntities((prev) => prev.filter((e) => e.value !== entity.value))}
                      />
                    ))}
                  </Box>
                  {manualEntities.length > 0 && (
                    <MUIAutocomplete
                      sx={{ mt: 2 }}
                      options={manualEntities}
                      getOptionLabel={(o) => o.label ?? ''}
                      value={entityValue}
                      isOptionEqualToValue={(o, v) => o.value === v.value}
                      onChange={(_, val) => setEntityValue(val as EntityValue | null)}
                      renderInput={(params) => (
                        <MUITextField {...params} label={t_i18n('Default entity (optional)')} fullWidth />
                      )}
                    />
                  )}
                </>
              )}
            </>
          )}

          {/* ── Vocabulary ── */}
          {fkt === 'vocabulary' && (
            <>
              <MUIAutocomplete
                sx={{ mt: 2 }}
                options={categoriesOptions}
                getOptionLabel={(o) => (typeof o === 'string' ? o : o.label)}
                value={categoriesOptions.find((o) => o.value === vocabCategory) ?? null}
                onChange={(_, val) => handleVocabCategoryChange((val as any)?.value ?? '')}
                renderInput={(params) => (
                  <MUITextField {...params} label={t_i18n('Vocabulary category')} fullWidth required />
                )}
              />
              {vocabCategory && (
                <>
                  <MUIAutocomplete
                    sx={{ mt: 2 }}
                    options={vocabOptions}
                    getOptionLabel={(o) => o.label}
                    value={vocabValue}
                    onChange={(_, val) => setVocabValue(val as VocabOption | null)}
                    renderInput={(params) => (
                      <MUITextField {...params} label={t_i18n('Vocabulary value (optional)')} fullWidth />
                    )}
                  />
                  <RestrictionModeSelect
                    value={restrictionMode}
                    onChange={setRestrictionMode}
                    options={[
                      { value: 'none', label: 'No restriction' },
                      { value: 'restricted', label: 'Restrict selectable values' },
                    ]}
                  />
                  {restrictionMode === 'restricted' && (
                    <SimpleMultiSelect
                      options={vocabOptions}
                      value={vocabRestricted}
                      onChange={setVocabRestricted}
                      label={t_i18n('Allowed values')}
                    />
                  )}
                </>
              )}
            </>
          )}

          {/* ── Kill chain phase ── */}
          {fkt === 'kill_chain' && (
            <>
              <MUIAutocomplete
                sx={{ mt: 2 }}
                options={killChainNames}
                value={killChainNameValue || null}
                onChange={(_, val) => {
                  setKillChainNameValue(val ?? '');
                  setKillChainValue(null);
                  setKillChainRestricted([]);
                }}
                renderInput={(params) => (
                  <MUITextField {...params} label={t_i18n('Kill chain name')} fullWidth required />
                )}
              />
              {killChainNameValue && (
                <>
                  <MUIAutocomplete
                    sx={{ mt: 2 }}
                    options={killChainPhasesForName}
                    getOptionLabel={(o) => o.phase_name}
                    value={killChainValue}
                    isOptionEqualToValue={(o, v) => o.value === v.value}
                    onChange={(_, val) => setKillChainValue(val as KillChainOption | null)}
                    renderInput={(params) => (
                      <MUITextField {...params} label={t_i18n('Default phase (optional)')} fullWidth />
                    )}
                  />
                  <RestrictionModeSelect
                    value={restrictionMode}
                    onChange={setRestrictionMode}
                    options={[
                      { value: 'none', label: 'No restriction' },
                      { value: 'restricted', label: 'Restrict selectable phases' },
                    ]}
                  />
                  {restrictionMode === 'restricted' && (
                    <MUIAutocomplete
                      multiple
                      sx={{ mt: 2 }}
                      options={killChainPhasesForName}
                      getOptionLabel={(o) => o.phase_name}
                      value={killChainRestricted}
                      isOptionEqualToValue={(o, v) => o.value === v.value}
                      onChange={(_, val) => setKillChainRestricted(val)}
                      renderInput={(params) => (
                        <MUITextField {...params} label={t_i18n('Allowed phases')} fullWidth />
                      )}
                    />
                  )}
                </>
              )}
            </>
          )}

          {/* ── Label selector ── */}
          {fkt === 'label' && (
            <>
              <MUIAutocomplete
                sx={{ mt: 2 }}
                options={labelOptions}
                getOptionLabel={(o) => o.label}
                value={labelValue}
                filterOptions={(x) => x}
                onOpen={() => searchLabels('')}
                onFocus={() => searchLabels('')}
                onInputChange={(_, val, reason) => {
                  if (reason === 'input' || reason === 'clear') {
                    searchLabels(val);
                  }
                }}
                onChange={(_, val) => setLabelValue(val as SimpleOption | null)}
                renderInput={(params) => (
                  <MUITextField {...params} label={t_i18n('Default label (optional)')} fullWidth />
                )}
              />
              <RestrictionModeSelect
                value={restrictionMode}
                onChange={setRestrictionMode}
                options={[
                  { value: 'none', label: 'No restriction' },
                  { value: 'restricted', label: 'Restrict selectable values' },
                ]}
              />
              {restrictionMode === 'restricted' && (
                <SimpleMultiSelect
                  options={labelOptions}
                  value={labelRestricted}
                  onChange={setLabelRestricted}
                  onOpen={() => searchLabels('')}
                  label={t_i18n('Allowed labels')}
                />
              )}
            </>
          )}

          {/* ── User selector ── */}
          {fkt === 'user' && (
            <>
              <MUIAutocomplete
                sx={{ mt: 2 }}
                options={userOptions}
                getOptionLabel={(o) => o.label}
                value={userValue}
                filterOptions={(x) => x}
                onOpen={() => searchUsers('')}
                onFocus={() => searchUsers('')}
                onInputChange={(_, val, reason) => {
                  if (reason === 'input' || reason === 'clear') {
                    searchUsers(val);
                  }
                }}
                onChange={(_, val) => setUserValue(val as SimpleOption | null)}
                renderInput={(params) => (
                  <MUITextField {...params} label={t_i18n('Default user (optional)')} fullWidth />
                )}
              />
              <RestrictionModeSelect
                value={restrictionMode}
                onChange={setRestrictionMode}
                options={[
                  { value: 'none', label: 'No restriction' },
                  { value: 'restricted', label: 'Restrict selectable values' },
                ]}
              />
              {restrictionMode === 'restricted' && (
                <SimpleMultiSelect
                  options={userOptions}
                  value={userRestricted}
                  onChange={setUserRestricted}
                  onOpen={() => searchUsers('')}
                  label={t_i18n('Allowed users')}
                />
              )}
            </>
          )}

          {/* ── Marking selector ── */}
          {fkt === 'marking' && (
            <>
              <MUIAutocomplete
                sx={{ mt: 2 }}
                options={markingOptions}
                getOptionLabel={(o) => o.label}
                value={markingValue}
                filterOptions={(x) => x}
                onOpen={() => searchMarkings('')}
                onFocus={() => searchMarkings('')}
                onInputChange={(_, val, reason) => {
                  if (reason === 'input' || reason === 'clear') {
                    searchMarkings(val);
                  }
                }}
                onChange={(_, val) => setMarkingValue(val as SimpleOption | null)}
                renderInput={(params) => (
                  <MUITextField {...params} label={t_i18n('Default marking (optional)')} fullWidth />
                )}
              />
              <RestrictionModeSelect
                value={restrictionMode}
                onChange={setRestrictionMode}
                options={[
                  { value: 'none', label: 'No restriction' },
                  { value: 'restricted', label: 'Restrict selectable values' },
                ]}
              />
              {restrictionMode === 'restricted' && (
                <SimpleMultiSelect
                  options={markingOptions}
                  value={markingRestricted}
                  onChange={setMarkingRestricted}
                  onOpen={() => searchMarkings('')}
                  label={t_i18n('Allowed markings')}
                />
              )}
            </>
          )}

          {/* ── Status ── */}
          {fkt === 'status' && (
            <>
              <MUIAutocomplete
                sx={{ mt: 2 }}
                options={statusOptions}
                getOptionLabel={(o) => o.label}
                value={statusValue}
                filterOptions={(x) => x}
                onOpen={() => searchStatuses('')}
                onFocus={() => searchStatuses('')}
                onInputChange={(_, val, reason) => {
                  if (reason === 'input' || reason === 'clear') {
                    searchStatuses(val);
                  }
                }}
                onChange={(_, val) => setStatusValue(val as SimpleOption | null)}
                renderInput={(params) => (
                  <MUITextField {...params} label={t_i18n('Default status (optional)')} fullWidth />
                )}
              />
              <RestrictionModeSelect
                value={restrictionMode}
                onChange={setRestrictionMode}
                options={[
                  { value: 'none', label: 'No restriction' },
                  { value: 'restricted', label: 'Restrict selectable values' },
                ]}
              />
              {restrictionMode === 'restricted' && (
                <SimpleMultiSelect
                  options={statusOptions}
                  value={statusRestricted}
                  onChange={setStatusRestricted}
                  onOpen={() => searchStatuses('')}
                  label={t_i18n('Allowed statuses')}
                />
              )}
            </>
          )}

          {/* ── Group selector ── */}
          {fkt === 'group' && (
            <>
              <MUIAutocomplete
                sx={{ mt: 2 }}
                options={groupOptions}
                getOptionLabel={(o) => o.label}
                value={groupValue}
                filterOptions={(x) => x}
                onOpen={() => searchGroups('')}
                onFocus={() => searchGroups('')}
                onInputChange={(_, val, reason) => {
                  if (reason === 'input' || reason === 'clear') {
                    searchGroups(val);
                  }
                }}
                onChange={(_, val) => setGroupValue(val as SimpleOption | null)}
                renderInput={(params) => (
                  <MUITextField {...params} label={t_i18n('Default group (optional)')} fullWidth />
                )}
              />
              <RestrictionModeSelect
                value={restrictionMode}
                onChange={setRestrictionMode}
                options={[
                  { value: 'none', label: 'No restriction' },
                  { value: 'restricted', label: 'Restrict selectable values' },
                ]}
              />
              {restrictionMode === 'restricted' && (
                <SimpleMultiSelect
                  options={groupOptions}
                  value={groupRestricted}
                  onChange={setGroupRestricted}
                  onOpen={() => searchGroups('')}
                  label={t_i18n('Allowed groups')}
                />
              )}
            </>
          )}

          {/* ── Date ── */}
          {fkt === 'date' && (
            <Box sx={{ mt: 2 }}>
              <DatePicker
                value={dateValue}
                label={t_i18n('Default date (optional)')}
                onChange={(value: Date | null, context) => !context.validationError && setDateValue(value)}
              />
            </Box>
          )}

          {/* ── Boolean: always defaults to false, no configuration needed ── */}

          {/* ── Numeric ── */}
          {fkt === 'numeric' && (
            <MUITextField
              fullWidth
              margin="normal"
              label={t_i18n('Value (optional)')}
              name="defaultValue"
              type="number"
              value={formik.values.defaultValue}
              onChange={formik.handleChange}
            />
          )}

          {/* ── Text ── */}
          {fkt === 'text' && (
            <MUITextField
              fullWidth
              margin="normal"
              label={t_i18n('Value (optional)')}
              name="defaultValue"
              value={formik.values.defaultValue}
              onChange={formik.handleChange}
            />
          )}

        </DialogContent>
        <DialogActions>
          <Button onClick={handleClose}>{t_i18n('Cancel')}</Button>
          <Button type="submit" variant="contained" disabled={formik.isSubmitting || !canSubmit}>
            {t_i18n('Add')}
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
};

export default VariableDefinitionDialog;
