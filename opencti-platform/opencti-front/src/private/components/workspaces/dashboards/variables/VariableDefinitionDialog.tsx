import React, { useEffect, useMemo, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import MUIAutocomplete from '@mui/material/Autocomplete';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import CircularProgress from '@mui/material/CircularProgress';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import FormControl from '@mui/material/FormControl';
import InputAdornment from '@mui/material/InputAdornment';
import InputLabel from '@mui/material/InputLabel';
import MenuItem from '@mui/material/MenuItem';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import MUITextField from '@mui/material/TextField';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import Typography from '@mui/material/Typography';
import { useFormik } from 'formik';
import EntitySelectWithTypes from '../../../../../components/fields/EntitySelectWithTypes';
import FilterIconButton from '../../../../../components/FilterIconButton';
import ItemIcon from '../../../../../components/ItemIcon';
import { useFormatter } from '../../../../../components/i18n';
import { fetchQuery } from '../../../../../relay/environment';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import useVocabularyCategory from '../../../../../utils/hooks/useVocabularyCategory';
import SearchScopeElement from '../../../common/lists/SearchScopeElement';
import Filters from '../../../common/lists/Filters';
import { killChainPhasesSearchQuery } from '../../../settings/KillChainPhases';
import { getNodes } from '../../../../../utils/connection';
import { KillChainPhasesSearchQuery$data } from '../../../settings/__generated__/KillChainPhasesSearchQuery.graphql';
import useFiltersState from '../../../../../utils/filters/useFiltersState';
import { removeFrontendIdAndEmptyFiltersFromFilterGroupObject, useAvailableFilterKeysForEntityTypes } from '../../../../../utils/filters/filtersUtils';
import { FilterOptionValue } from '../../../common/lists/FilterAutocomplete';
import { vocabularySearchQuery } from '../../../settings/VocabularyQuery';
import { serializeEntityPickerRestriction, EntityPickerRestrictionMode } from './entityPickerRestriction';

const SEARCH_FILTER_KEY = 'id';

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
      }
    }
  }
`;

const stixCoreObjectsSearchQuery = graphql`
  query VariableDefinitionDialogStixCoreObjectsSearchQuery(
    $search: String
    $types: [String]
    $count: Int
    $filters: FilterGroup
  ) {
    stixCoreObjects(
      search: $search
      types: $types
      first: $count
      filters: $filters
    ) {
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

type FilterKeyType = 'entity_ref' | 'label' | 'marking' | 'entity_type' | 'relation_type' | 'user' | 'vocabulary' | 'kill_chain' | 'boolean' | 'numeric' | 'text';

const FILTER_KEY_TYPES: Array<{ value: FilterKeyType; label: string }> = [
  { value: 'entity_ref', label: 'Entity selector' },
  { value: 'label', label: 'Label picker' },
  { value: 'marking', label: 'Marking picker' },
  { value: 'entity_type', label: 'Entity type picker' },
  { value: 'relation_type', label: 'Relation type picker' },
  { value: 'user', label: 'User picker' },
  { value: 'vocabulary', label: 'Vocabulary' },
  { value: 'kill_chain', label: 'Kill chain phase' },
  { value: 'boolean', label: 'Boolean' },
  { value: 'numeric', label: 'Numeric' },
  { value: 'text', label: 'Text' },
];

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

interface VariableDefinitionDialogProps {
  open: boolean;
  workspaceId: string;
  onClose: () => void;
}

const mapEntityEdgesToOptions = (data: any): FilterOptionValue[] => {
  return (data?.stixCoreObjects?.edges ?? []).flatMap((edge: any) => {
    const node = edge?.node;
    if (!node?.id) {
      return [];
    }
    return [{
      value: node.id,
      label: node.representative?.main ?? node.id,
      type: node.entity_type,
    }];
  });
};

const VariableDefinitionDialog: React.FC<VariableDefinitionDialogProps> = ({
  open,
  workspaceId,
  onClose,
}) => {
  const { t_i18n } = useFormatter();
  const [commitAdd] = useApiMutation(variableAddMutation);
  const { categoriesOptions } = useVocabularyCategory();
  const availableEntityFilterKeys = useAvailableFilterKeysForEntityTypes(['Stix-Core-Object']);

  const [entityPickerMode, setEntityPickerMode] = useState<EntityPickerRestrictionMode>('no_restriction');
  const [noRestrictionDefaultEntity, setNoRestrictionDefaultEntity] = useState<FilterOptionValue | null>(null);
  const [filterModeDefaultEntity, setFilterModeDefaultEntity] = useState<FilterOptionValue | null>(null);
  const [selectModeEntities, setSelectModeEntities] = useState<FilterOptionValue[]>([]);
  const [filterModeSearchScope, setFilterModeSearchScope] = useState<Record<string, string[]>>({});
  const [selectModeSearchScope, setSelectModeSearchScope] = useState<Record<string, string[]>>({});
  const [filterModeInputValue, setFilterModeInputValue] = useState('');
  const [selectModeInputValue, setSelectModeInputValue] = useState('');
  const [entityOptions, setEntityOptions] = useState<FilterOptionValue[]>([]);
  const [isEntityOptionsLoading, setIsEntityOptionsLoading] = useState(false);
  const [entityAutocompleteOpen, setEntityAutocompleteOpen] = useState(false);
  const [filterModeFilters, filterModeFilterHelpers] = useFiltersState();
  const requestCounterRef = useRef(0);

  const [vocabCategory, setVocabCategory] = useState<string>('');
  const [vocabOptions, setVocabOptions] = useState<VocabOption[]>([]);
  const [vocabValue, setVocabValue] = useState<VocabOption | null>(null);

  const [killChainOptions, setKillChainOptions] = useState<KillChainOption[]>([]);
  const [killChainValue, setKillChainValue] = useState<KillChainOption | null>(null);

  const asStringOrNull = (value: unknown): string | null => {
    if (value === null || value === undefined || value === '') {
      return null;
    }
    return String(value);
  };

  const searchEntitiesForEntityPicker = (
    search: string,
    currentFilterKeyType: FilterKeyType,
    mode: EntityPickerRestrictionMode,
  ) => {
    if (currentFilterKeyType !== 'entity_ref' || mode === 'no_restriction') {
      return;
    }

    requestCounterRef.current += 1;
    const requestId = requestCounterRef.current;
    setIsEntityOptionsLoading(true);

    const selectedScope = mode === 'filter' ? filterModeSearchScope : selectModeSearchScope;
    const filters = mode === 'filter'
      ? removeFrontendIdAndEmptyFiltersFromFilterGroupObject(filterModeFilters)
      : undefined;

    fetchQuery(stixCoreObjectsSearchQuery, {
      search,
      count: 100,
      types: selectedScope[SEARCH_FILTER_KEY]?.length ? selectedScope[SEARCH_FILTER_KEY] : undefined,
      filters,
    })
      .toPromise()
      .then((data: any) => {
        if (requestCounterRef.current !== requestId) {
          return;
        }
        setEntityOptions(mapEntityEdgesToOptions(data));
      })
      .catch(() => {
        if (requestCounterRef.current !== requestId) {
          return;
        }
        setEntityOptions([]);
      })
      .finally(() => {
        if (requestCounterRef.current === requestId) {
          setIsEntityOptionsLoading(false);
        }
      });
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
      if (values.filterKeyType === 'entity_ref' && entityPickerMode === 'no_restriction' && !noRestrictionDefaultEntity?.value) {
        errors.defaultValue = t_i18n('Default entity is required in no restriction mode');
      }
      if (values.filterKeyType === 'entity_ref' && entityPickerMode === 'filter' && !filterModeDefaultEntity?.value) {
        errors.defaultValue = t_i18n('Default entity is required in filter mode');
      }
      if (values.filterKeyType === 'entity_ref' && entityPickerMode === 'selection' && selectModeEntities.length === 0) {
        errors.defaultValue = t_i18n('Select at least one entity');
      }
      return errors;
    },
    onSubmit: (values, { resetForm }) => {
      const entityDefaultValue = serializeEntityPickerRestriction(
        entityPickerMode,
        noRestrictionDefaultEntity?.value,
        filterModeDefaultEntity?.value,
        filterModeFilters,
        selectModeEntities.map((entity) => entity.value),
      );
      commitAdd({
        variables: {
          id: workspaceId,
          input: {
            name: values.name,
            filterKey: values.filterKeyType === 'vocabulary'
              ? (vocabCategory || 'vocabulary')
              : values.filterKeyType,
            filterKeyType: values.filterKeyType,
            defaultValue: values.filterKeyType === 'entity_ref'
              ? entityDefaultValue
              : (values.filterKeyType === 'vocabulary'
                ? asStringOrNull(vocabValue?.value)
                : values.filterKeyType === 'kill_chain'
                  ? (killChainValue
                    ? JSON.stringify({
                      kill_chain_name: killChainValue.kill_chain_name,
                      phase_name: killChainValue.phase_name,
                    })
                    : null)
                  : asStringOrNull(values.defaultValue)),
          },
        },
        onCompleted: () => {
          resetForm();
          setEntityPickerMode('no_restriction');
          setNoRestrictionDefaultEntity(null);
          setFilterModeDefaultEntity(null);
          setSelectModeEntities([]);
          setFilterModeSearchScope({});
          setSelectModeSearchScope({});
          setFilterModeInputValue('');
          setSelectModeInputValue('');
          setEntityOptions([]);
          setEntityAutocompleteOpen(false);
          filterModeFilterHelpers.handleClearAllFilters();
          setVocabCategory('');
          setVocabOptions([]);
          setVocabValue(null);
          setKillChainOptions([]);
          setKillChainValue(null);
          onClose();
        },
      });
    },
  });

  const fkt = formik.values.filterKeyType;

  useEffect(() => {
    if (fkt === 'entity_ref' && entityPickerMode === 'filter' && entityAutocompleteOpen) {
      searchEntitiesForEntityPicker(filterModeInputValue, fkt, entityPickerMode);
    }
  }, [fkt, entityPickerMode, entityAutocompleteOpen, filterModeInputValue, filterModeFilters, filterModeSearchScope]);

  const resetExtraState = () => {
    setEntityPickerMode('no_restriction');
    setNoRestrictionDefaultEntity(null);
    setFilterModeDefaultEntity(null);
    setSelectModeEntities([]);
    setFilterModeSearchScope({});
    setSelectModeSearchScope({});
    setFilterModeInputValue('');
    setSelectModeInputValue('');
    setEntityOptions([]);
    setEntityAutocompleteOpen(false);
    filterModeFilterHelpers.handleClearAllFilters();
    setVocabCategory('');
    setVocabOptions([]);
    setVocabValue(null);
    setKillChainOptions([]);
    setKillChainValue(null);
  };

  const handleVocabCategoryChange = (category: string) => {
    setVocabCategory(category);
    setVocabValue(null);
    if (!category) return;
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

  const filterModeOptions = useMemo(() => {
    if (!filterModeDefaultEntity) {
      return entityOptions;
    }
    const hasDefault = entityOptions.some((option) => option.value === filterModeDefaultEntity.value);
    return hasDefault ? entityOptions : [filterModeDefaultEntity, ...entityOptions];
  }, [entityOptions, filterModeDefaultEntity]);

  const selectModeOptions = useMemo(() => {
    const mapById = new Map<string, FilterOptionValue>();
    selectModeEntities.forEach((entity) => mapById.set(entity.value, entity));
    entityOptions.forEach((entity) => mapById.set(entity.value, entity));
    return [...mapById.values()];
  }, [entityOptions, selectModeEntities]);

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

  return (
    <Dialog open={open} onClose={handleClose} fullWidth maxWidth="sm">
      <form onSubmit={formik.handleSubmit}>
        <DialogTitle>{t_i18n('Add dashboard variable')}</DialogTitle>
        <DialogContent>
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

          {fkt === 'entity_ref' && (
            <Box sx={{ mt: 2 }}>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                {t_i18n('Restriction')}
              </Typography>
              <ToggleButtonGroup
                value={entityPickerMode}
                exclusive
                size="small"
                onChange={(_, value) => {
                  if (value) {
                    setEntityPickerMode(value);
                    setEntityAutocompleteOpen(false);
                  }
                }}
                sx={{ mb: 2, display: 'flex', flexWrap: 'wrap', gap: 1 }}
              >
                <ToggleButton value="no_restriction">{t_i18n('No restriction')}</ToggleButton>
                <ToggleButton value="filter">{t_i18n('Filter mode')}</ToggleButton>
                <ToggleButton value="selection">{t_i18n('Select entity mode')}</ToggleButton>
              </ToggleButtonGroup>

              {entityPickerMode === 'no_restriction' && (
                <>
                  <EntitySelectWithTypes
                    label={t_i18n('Default entity')}
                    value={noRestrictionDefaultEntity}
                    handleChange={(val: FilterOptionValue) => setNoRestrictionDefaultEntity(val)}
                    entitiesToExclude={[]}
                  />
                  {formik.submitCount > 0 && formik.errors.defaultValue && (
                    <Typography variant="caption" color="error" sx={{ display: 'block', mt: 1 }}>
                      {formik.errors.defaultValue}
                    </Typography>
                  )}
                </>
              )}

              {entityPickerMode === 'filter' && (
                <>
                  <Box sx={{ mb: 1 }}>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      {t_i18n('Filters')}
                    </Typography>
                    <Filters
                      availableFilterKeys={availableEntityFilterKeys}
                      helpers={filterModeFilterHelpers}
                      searchContext={{ entityTypes: ['Stix-Core-Object'] }}
                    />
                    <Box sx={{ mt: 1 }}>
                      <FilterIconButton
                        filters={filterModeFilters}
                        helpers={filterModeFilterHelpers}
                        entityTypes={['Stix-Core-Object']}
                        searchContext={{ entityTypes: ['Stix-Core-Object'] }}
                      />
                    </Box>
                  </Box>
                  <MUIAutocomplete
                    sx={{ mt: 2 }}
                    options={filterModeOptions}
                    getOptionLabel={(option) => option.label ?? ''}
                    value={filterModeDefaultEntity}
                    inputValue={filterModeInputValue}
                    filterOptions={(x) => x}
                    open={entityAutocompleteOpen}
                    onOpen={() => {
                      setEntityAutocompleteOpen(true);
                      searchEntitiesForEntityPicker(filterModeInputValue, fkt, entityPickerMode);
                    }}
                    onClose={() => setEntityAutocompleteOpen(false)}
                    onInputChange={(_event, value, reason) => {
                      setFilterModeInputValue(value);
                      if (reason === 'input' || reason === 'clear') {
                        searchEntitiesForEntityPicker(value, fkt, entityPickerMode);
                      }
                    }}
                    onChange={(_event, value) => {
                      setFilterModeDefaultEntity(value as FilterOptionValue | null);
                    }}
                    isOptionEqualToValue={(option, value) => option.value === value.value}
                    noOptionsText={t_i18n('No available options')}
                    renderInput={(params) => (
                      <MUITextField
                        {...params}
                        label={t_i18n('Default entity')}
                        fullWidth
                        slotProps={{
                          input: {
                            ...params.InputProps,
                            endAdornment: (
                              <InputAdornment position="end" sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                {isEntityOptionsLoading ? <CircularProgress size={14} /> : null}
                                <SearchScopeElement
                                  name={SEARCH_FILTER_KEY}
                                  searchScope={filterModeSearchScope}
                                  setSearchScope={setFilterModeSearchScope}
                                />
                                {params.InputProps.endAdornment}
                              </InputAdornment>
                            ),
                          },
                        }}
                      />
                    )}
                    renderOption={(props, option) => (
                      <li {...props}>
                        <ItemIcon type={option.type} color={option.color} />
                        <span style={{ marginLeft: 8 }}>{option.label}</span>
                      </li>
                    )}
                  />
                  {formik.submitCount > 0 && formik.errors.defaultValue && (
                    <Typography variant="caption" color="error" sx={{ display: 'block', mt: 1 }}>
                      {formik.errors.defaultValue}
                    </Typography>
                  )}
                </>
              )}

              {entityPickerMode === 'selection' && (
                <>
                  <MUIAutocomplete
                    multiple
                    disableCloseOnSelect
                    sx={{ mt: 2 }}
                    options={selectModeOptions}
                    getOptionLabel={(option) => option.label ?? ''}
                    value={selectModeEntities}
                    inputValue={selectModeInputValue}
                    filterOptions={(x) => x}
                    isOptionEqualToValue={(option, value) => option.value === value.value}
                    noOptionsText={t_i18n('No available options')}
                    onOpen={() => searchEntitiesForEntityPicker(selectModeInputValue, fkt, entityPickerMode)}
                    onInputChange={(_event, value, reason) => {
                      setSelectModeInputValue(value);
                      if (reason === 'input' || reason === 'clear') {
                        searchEntitiesForEntityPicker(value, fkt, entityPickerMode);
                      }
                    }}
                    onChange={(_event, value) => {
                      setSelectModeEntities(value as FilterOptionValue[]);
                    }}
                    renderTags={(value, getTagProps) => value.map((option, index) => (
                      <Chip
                        {...getTagProps({ index })}
                        key={option.value}
                        label={option.label}
                        variant="outlined"
                      />
                    ))}
                    renderInput={(params) => (
                      <MUITextField
                        {...params}
                        label={t_i18n('Select entity')}
                        fullWidth
                        helperText={selectModeEntities.length > 0
                          ? t_i18n('The first selected entity will be used as default')
                          : undefined}
                        slotProps={{
                          input: {
                            ...params.InputProps,
                            endAdornment: (
                              <InputAdornment position="end" sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                {isEntityOptionsLoading ? <CircularProgress size={14} /> : null}
                                <SearchScopeElement
                                  name={SEARCH_FILTER_KEY}
                                  searchScope={selectModeSearchScope}
                                  setSearchScope={setSelectModeSearchScope}
                                />
                                {params.InputProps.endAdornment}
                              </InputAdornment>
                            ),
                          },
                        }}
                      />
                    )}
                    renderOption={(props, option) => (
                      <li {...props}>
                        <ItemIcon type={option.type} color={option.color} />
                        <span style={{ marginLeft: 8 }}>{option.label}</span>
                      </li>
                    )}
                  />
                  {formik.submitCount > 0 && formik.errors.defaultValue && (
                    <Typography variant="caption" color="error" sx={{ display: 'block', mt: 1 }}>
                      {formik.errors.defaultValue}
                    </Typography>
                  )}
                </>
              )}
            </Box>
          )}

          {fkt === 'vocabulary' && (
            <>
              <MUIAutocomplete
                sx={{ mt: 2 }}
                options={categoriesOptions}
                getOptionLabel={(o) => (typeof o === 'string' ? o : o.label)}
                value={categoriesOptions.find((o) => o.value === vocabCategory) ?? null}
                onChange={(_event, val) => handleVocabCategoryChange((val as any)?.value ?? '')}
                renderInput={(params) => (
                  <MUITextField {...params} label={t_i18n('Vocabulary category')} fullWidth />
                )}
              />
              {vocabCategory && (
                <MUIAutocomplete
                  sx={{ mt: 2 }}
                  options={vocabOptions}
                  getOptionLabel={(o) => o.label}
                  value={vocabValue}
                  onChange={(_event, val) => setVocabValue(val as VocabOption | null)}
                  renderInput={(params) => (
                    <MUITextField {...params} label={t_i18n('Vocabulary value (optional)')} fullWidth />
                  )}
                />
              )}
            </>
          )}

          {fkt === 'kill_chain' && (
            <MUIAutocomplete
              sx={{ mt: 2 }}
              options={killChainOptions}
              getOptionLabel={(o) => o.label}
              value={killChainValue}
              filterOptions={(x) => x}
              onOpen={() => searchKillChains('')}
              onFocus={() => searchKillChains('')}
              onInputChange={(_event, val, reason) => {
                if (reason === 'input' || reason === 'clear') {
                  searchKillChains(val);
                }
              }}
              onChange={(_event, val) => setKillChainValue(val as KillChainOption | null)}
              renderInput={(params) => (
                <MUITextField {...params} label={t_i18n('Kill chain phase (optional)')} fullWidth />
              )}
            />
          )}

          {fkt === 'boolean' && (
            <FormControl fullWidth margin="normal">
              <InputLabel>{t_i18n('Value (optional)')}</InputLabel>
              <Select
                name="defaultValue"
                value={formik.values.defaultValue}
                onChange={formik.handleChange}
                label={t_i18n('Value (optional)')}
              >
                <MenuItem value="">{t_i18n('No default')}</MenuItem>
                <MenuItem value="true">true</MenuItem>
                <MenuItem value="false">false</MenuItem>
              </Select>
            </FormControl>
          )}

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
          <Button
            type="submit"
            variant="contained"
            disabled={formik.isSubmitting}
          >
            {t_i18n('Add')}
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
};

export default VariableDefinitionDialog;


