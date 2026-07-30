import React, { Dispatch, Suspense, SyntheticEvent, useMemo, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Chip from '@mui/material/Chip';
import Popover from '@mui/material/Popover';
import TextField from '@mui/material/TextField';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import InputAdornment from '@mui/material/InputAdornment';
import IconButton from '@mui/material/IconButton';
import CloseOutlined from '@mui/icons-material/CloseOutlined';
import ArrowDropDownOutlined from '@mui/icons-material/ArrowDropDownOutlined';
import DeleteOutlined from '@mui/icons-material/DeleteOutlined';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import { Autocomplete } from '@mui/material';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../../components/i18n';
import { fetchQuery } from '../../../../../relay/environment';
import useAuth from '../../../../../utils/hooks/useAuth';
import { convertMarking } from '../../../../../utils/edition';
import { displayEntityTypeForTranslation } from '../../../../../utils/String';
import type { VariableValueControlEntityLabelQuery } from './__generated__/VariableValueControlEntityLabelQuery.graphql';
import useSearchEntities from '../../../../../utils/filters/useSearchEntities';
import SearchScopeElement from '../../../common/lists/SearchScopeElement';
import { FilterOptionValue } from '../../../common/lists/FilterAutocomplete';
import ItemIcon from '../../../../../components/ItemIcon';
import { useDashboardVariables } from './DashboardVariablesContext';
import { vocabularySearchQuery } from '../../../settings/VocabularyQuery';
import { labelsSearchQuery } from '../../../settings/LabelsQuery';
import { parseEntityPickerRestriction } from './entityPickerRestriction';

const setValueMutation = graphql`
  mutation VariableValueControlSetMutation($workspaceId: ID!, $variableId: ID!, $value: String) {
    workspaceVariableSetValue(workspaceId: $workspaceId, variableId: $variableId, value: $value) {
      id
      variable_values
    }
  }
`;

const resetValueMutation = graphql`
  mutation VariableValueControlResetMutation($workspaceId: ID!, $variableId: ID!) {
    workspaceVariableResetValue(workspaceId: $workspaceId, variableId: $variableId) {
      id
      variable_values
    }
  }
`;

const deleteVariableMutation = graphql`
  mutation VariableValueControlDeleteMutation($id: ID!, $variableId: ID!) {
    workspaceVariableDelete(id: $id, variableId: $variableId)
  }
`;

const entityLabelQuery = graphql`
  query VariableValueControlEntityLabelQuery($filters: FilterGroup!) {
    filtersRepresentatives(filters: $filters) {
      value
    }
  }
`;

const usersSearchQuery = graphql`
  query VariableValueControlUsersSearchQuery($search: String, $first: Int, $orderBy: UsersOrdering, $orderMode: OrderingMode) {
    users(search: $search, first: $first, orderBy: $orderBy, orderMode: $orderMode) {
      edges {
        node {
          id
          name
          entity_type
        }
      }
    }
  }
`;

const restrictedEntityOptionsQuery = graphql`
  query VariableValueControlRestrictedEntityOptionsQuery(
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

/** Resolves the display label for an entity-ref variable value using filtersRepresentatives. */
const EntityRefLabel: React.FC<{ entityId: string; fallback: string }> = ({ entityId, fallback }) => {
  const data = useLazyLoadQuery<VariableValueControlEntityLabelQuery>(
    entityLabelQuery,
    {
      filters: {
        mode: 'and',
        filters: [{ key: 'ids', values: [entityId], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
    },
    { fetchPolicy: 'store-or-network' },
  );
  const label = data.filtersRepresentatives?.[0]?.value;
  return <>{label ?? fallback}</>;
};

interface VariableValueControlProps {
  workspaceId: string;
  variableId: string;
  variableName: string;
  filterKey?: string;
  filterKeyType: string | null | undefined;
  isUsedInWidgets?: boolean;
  currentValue: string | null | undefined;
  defaultValue: string | null | undefined;
  onVariableDeleted?: (variableId: string) => void;
}

interface VocabOption {
  label: string;
  value: string;
  categoryKey?: string;
}

interface KillChainSerializedValue {
  kill_chain_name?: string;
  phase_name?: string;
}

interface GenericOption {
  label: string;
  value: string;
  type?: string;
  color?: string;
}

const VariableValueControl: React.FC<VariableValueControlProps> = ({
  workspaceId,
  variableId,
  variableName,
  filterKey,
  filterKeyType,
  isUsedInWidgets = false,
  currentValue,
  defaultValue,
  onVariableDeleted,
}) => {
  const ENTITY_REF_FILTER_KEY = 'id';
  const { t_i18n } = useFormatter();
  const { setVariableValue } = useDashboardVariables();
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [inputValue, setInputValue] = useState(currentValue ?? defaultValue ?? '');
  const [entityInputValue, setEntityInputValue] = useState('');
  const [entityDraftValue, setEntityDraftValue] = useState<FilterOptionValue | null>(null);
  const [entityAutocompleteOpen, setEntityAutocompleteOpen] = useState(false);
  const [restrictedEntityOptions, setRestrictedEntityOptions] = useState<FilterOptionValue[]>([]);
  const [vocabOptions, setVocabOptions] = useState<VocabOption[]>([]);
  const [vocabInputValue, setVocabInputValue] = useState('');
  const [commitSet] = useApiMutation(setValueMutation);
  const [commitReset] = useApiMutation(resetValueMutation);
  const [commitDelete] = useApiMutation(deleteVariableMutation);

  // Entity search state for entity_ref variables
  const [searchScope, setSearchScope] = useState<Record<string, string[]>>({});
  const [cacheEntities, setCacheEntities] = useState<Record<string, { label: string; value: string; type: string }[]>>({});
  const [, setInputValues] = useState<{ key: string; values: string[] }[]>([]);
  const [entities, searchEntities] = useSearchEntities({
    searchContext: { entityTypes: ['Stix-Core-Object'] },
    searchScope,
    setInputValues,
    availableEntityTypes: undefined,
    availableRelationshipTypes: undefined,
  }) as [
    Record<string, FilterOptionValue[]>,
    (
      filterKey: string,
      cacheEntities: Record<string, { label: string; value: string; type: string }[]>,
      setCacheEntities: Dispatch<Record<string, { label: string; value: string; type: string }[]>>,
      event: SyntheticEvent,
    ) => Record<string, FilterOptionValue[]>,
  ];

  const parsedEntityRestriction = filterKeyType === 'entity_ref'
    ? parseEntityPickerRestriction(defaultValue ?? null)
    : null;
  const entityDefaultValue = parsedEntityRestriction?.defaultEntityId ?? defaultValue ?? null;
  const effectiveValue = currentValue ?? entityDefaultValue;
  const isOverridden = currentValue !== null && currentValue !== undefined;
  const isVocabulary = filterKeyType === 'vocabulary';
  const usesRestrictedEntityOptions = filterKeyType === 'entity_ref' && parsedEntityRestriction?.mode !== 'no_restriction';

  const loadRestrictedEntityOptions = (search = '') => {
    if (filterKeyType !== 'entity_ref') {
      return;
    }

    const restriction = parseEntityPickerRestriction(defaultValue ?? null);
    if (!restriction || restriction.mode === 'no_restriction') {
      return;
    }

    const scopeTypes = searchScope[ENTITY_REF_FILTER_KEY]?.length > 0
      ? searchScope[ENTITY_REF_FILTER_KEY]
      : undefined;

    const baseFilters = restriction.mode === 'filter'
      ? restriction.filterGroup
      : {
          mode: 'and',
          filters: [{
            key: 'ids',
            values: restriction.selectedEntityIds,
            operator: 'eq',
            mode: 'or',
          }],
          filterGroups: [],
        };

    fetchQuery(restrictedEntityOptionsQuery, {
      search,
      count: 100,
      types: scopeTypes,
      filters: baseFilters,
    })
      .toPromise()
      .then((data: any) => {
        const options: FilterOptionValue[] = (data?.stixCoreObjects?.edges ?? [])
          .flatMap((edge: any) => {
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
        setRestrictedEntityOptions(options);
      })
      .catch(() => {
        setRestrictedEntityOptions([]);
      });
  };

  const handleOpen = (event: React.MouseEvent<HTMLElement>) => {
    setInputValue(currentValue ?? defaultValue ?? '');
    setEntityDraftValue(selectedEntityOption);
    setEntityInputValue(selectedEntityOption?.label ?? '');
    setVocabInputValue(currentValue ?? defaultValue ?? '');
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => setAnchorEl(null);

  const handleApply = () => {
    commitSet({
      variables: { workspaceId, variableId, value: inputValue },
      onCompleted: () => {
        setVariableValue(variableId, inputValue || null);
        handleClose();
      },
    });
  };

  const handleReset = () => {
    commitReset({
      variables: { workspaceId, variableId },
      onCompleted: () => {
        setVariableValue(variableId, null);
        handleClose();
      },
    });
  };

  const isEntityRef = filterKeyType === 'entity_ref';
  const isBoolean = filterKeyType === 'boolean';
  const isKillChain = filterKeyType === 'kill_chain';
  const displayValue = effectiveValue ?? t_i18n('(not set)');
  const isHighlighted = isUsedInWidgets;
  const variableTypeLabel = (() => {
    switch (filterKeyType) {
      case 'entity_ref': return t_i18n('Entity picker');
      case 'boolean': return t_i18n('Boolean');
      case 'vocabulary': return t_i18n('Vocabulary');
      case 'numeric': return t_i18n('Number');
      case 'kill_chain': return t_i18n('Kill chain phase');
      case 'text': return t_i18n('Text');
      default: return filterKeyType ?? '';
    }
  })();

  const handleDeleteVariable = () => {
    commitDelete({
      variables: { id: workspaceId, variableId },
      updater: (store) => {
        const workspaceRecord = store.get(workspaceId);
        if (!workspaceRecord) {
          return;
        }
        const currentVariables = workspaceRecord.getLinkedRecords('variables') ?? [];
        const nextVariables = currentVariables.filter((variableRecord) => variableRecord.getDataID() !== variableId);
        workspaceRecord.setLinkedRecords(nextVariables, 'variables');
      },
      onCompleted: () => {
        setVariableValue(variableId, null);
        onVariableDeleted?.(variableId);
        handleClose();
      },
    });
  };

  const entityLabelData = useLazyLoadQuery<VariableValueControlEntityLabelQuery>(
    entityLabelQuery,
    {
      filters: {
        mode: 'and',
        filters: effectiveValue
          ? [{ key: 'ids', values: [effectiveValue], operator: 'eq', mode: 'or' }]
          : [],
        filterGroups: [],
      },
    },
    { fetchPolicy: 'store-or-network' },
  );

  const chipLabel = (
    <>
      {`${variableName}: `}
      {isEntityRef && effectiveValue ? (
        <Suspense fallback={<>{displayValue}</>}>
          <EntityRefLabel entityId={effectiveValue} fallback={displayValue} />
        </Suspense>
      ) : isKillChain && effectiveValue ? (
        (() => {
          try {
            const parsed = JSON.parse(effectiveValue) as KillChainSerializedValue;
            if (parsed.kill_chain_name && parsed.phase_name) {
              return `[${parsed.kill_chain_name}] ${parsed.phase_name}`;
            }
            return displayValue;
          } catch {
            return displayValue;
          }
        })()
      ) : displayValue}
    </>
  );

  const dynamicEntityOptions: FilterOptionValue[] = searchScope[ENTITY_REF_FILTER_KEY]?.length > 0
    ? (entities[ENTITY_REF_FILTER_KEY] ?? []).filter((n) => searchScope[ENTITY_REF_FILTER_KEY].some((s) => (n.parentTypes ?? []).concat(n.type).includes(s)))
    : (entities[ENTITY_REF_FILTER_KEY] ?? []);
  const entityOptions = usesRestrictedEntityOptions ? restrictedEntityOptions : dynamicEntityOptions;

  const selectedEntityOption = useMemo<FilterOptionValue | null>(() => {
    if (!isEntityRef || !effectiveValue) return null;
    const selectedInOptions = entityOptions.find((option) => option.value === effectiveValue);
    if (selectedInOptions) return selectedInOptions;
    return {
      value: effectiveValue,
      label: entityLabelData.filtersRepresentatives?.[0]?.value ?? effectiveValue,
      type: 'Stix-Core-Object',
    };
  }, [isEntityRef, effectiveValue, entityOptions, entityLabelData.filtersRepresentatives]);

  const selectedVocabOption = useMemo<VocabOption | null>(() => {
    if (!isVocabulary || !effectiveValue) return null;
    const existing = vocabOptions.find((option) => option.value === effectiveValue);
    if (existing) return existing;
    return { label: effectiveValue, value: effectiveValue };
  }, [effectiveValue, isVocabulary, vocabOptions]);

  const loadVocabularyOptions = (search = '') => {
    const category = filterKey && filterKey !== 'vocabulary' ? filterKey : undefined;
    fetchQuery(vocabularySearchQuery, { category, search }).toPromise().then((data: any) => {
      const options: VocabOption[] = (data?.vocabularies?.edges ?? []).map((edge: any) => ({
        label: edge.node.name,
        value: edge.node.name,
        categoryKey: edge.node?.category?.key,
      }));
      setVocabOptions(options);
    });
  };

  const resolvedVocabularyCategory = useMemo(() => {
    if (filterKey && filterKey !== 'vocabulary') {
      return filterKey;
    }
    if (!effectiveValue) {
      return null;
    }
    const match = vocabOptions.find((option) => option.value === effectiveValue);
    return match?.categoryKey ?? null;
  }, [effectiveValue, filterKey, vocabOptions]);

  return (
    <>
      <Chip
        label={chipLabel}
        onClick={handleOpen}
        color={isHighlighted ? 'primary' : 'default'}
        size="small"
        variant={isHighlighted ? 'filled' : 'outlined'}
      />
      <Popover
        open={Boolean(anchorEl)}
        anchorEl={anchorEl}
        onClose={handleClose}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
      >
        <Box sx={{ p: 2, minWidth: 340 }}>
          <Typography variant="caption" color="text.secondary">
            {t_i18n('Variable name')}
          </Typography>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            {variableName}
          </Typography>

          <Typography variant="caption" color="text.secondary">
            {t_i18n('Variable type')}
          </Typography>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            {variableTypeLabel}
          </Typography>

          {isVocabulary && (
            <>
              <Typography variant="caption" color="text.secondary">
                {t_i18n('Open vocabulary')}
              </Typography>
              <Typography variant="body2" sx={{ mb: 1.5 }}>
                {resolvedVocabularyCategory ?? t_i18n('All categories')}
              </Typography>
            </>
          )}

          <Typography variant="caption" color="text.secondary">
            {t_i18n('Variable value')}
          </Typography>
          {isEntityRef ? (
            <Autocomplete
              size="small"
              fullWidth
              openOnFocus
              forcePopupIcon={false}
              open={entityAutocompleteOpen}
              onOpen={() => {
                setEntityAutocompleteOpen(true);
                if (usesRestrictedEntityOptions) {
                  loadRestrictedEntityOptions('');
                }
              }}
              onClose={() => setEntityAutocompleteOpen(false)}
              value={entityDraftValue}
              inputValue={entityInputValue}
              getOptionLabel={(option) => option.label ?? ''}
              noOptionsText={t_i18n('No available options')}
              options={entityOptions}
              groupBy={(option) => t_i18n(option.group ?? option.type)}
              filterOptions={(x) => x}
              onInputChange={(event, newInputValue, reason) => {
                setEntityInputValue(newInputValue);
                if (reason === 'clear') {
                  setEntityDraftValue(null);
                }
                if (usesRestrictedEntityOptions) {
                  loadRestrictedEntityOptions(newInputValue);
                } else {
                  searchEntities(ENTITY_REF_FILTER_KEY, cacheEntities, setCacheEntities, event);
                }
              }}
              onChange={(_event, option) => {
                setEntityDraftValue(option);
                if (!option) return;
                commitSet({
                  variables: { workspaceId, variableId, value: option.value },
                  onCompleted: () => {
                    setVariableValue(variableId, option.value);
                    handleClose();
                  },
                });
              }}
              onFocus={(event) => {
                setEntityAutocompleteOpen(true);
                if (usesRestrictedEntityOptions) {
                  loadRestrictedEntityOptions('');
                } else {
                  searchEntities(ENTITY_REF_FILTER_KEY, cacheEntities, setCacheEntities, event);
                }
              }}
              isOptionEqualToValue={(option, val) => option.value === val.value}
              renderInput={(params) => (
                <TextField
                  {...params}
                  placeholder={t_i18n('Select a value')}
                  variant="outlined"
                  size="small"
                  fullWidth
                  slotProps={{
                    input: {
                      ...params.InputProps,
                      endAdornment: (
                        <InputAdornment position="end" sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mr: 3 }}>
                          {entityDraftValue && (
                            <IconButton
                              size="small"
                              aria-label={t_i18n('Clear selection')}
                              onClick={(event) => {
                                event.preventDefault();
                                event.stopPropagation();
                                setEntityDraftValue(null);
                                setEntityInputValue('');
                              }}
                            >
                              <CloseOutlined fontSize="small" />
                            </IconButton>
                          )}
                          <IconButton
                            size="small"
                            aria-label={t_i18n('Open menu')}
                            onClick={(event) => {
                              event.preventDefault();
                              event.stopPropagation();
                              setEntityAutocompleteOpen((prev) => !prev);
                            }}
                          >
                            <ArrowDropDownOutlined fontSize="small" />
                          </IconButton>
                          <SearchScopeElement
                            name={ENTITY_REF_FILTER_KEY}
                            searchScope={searchScope}
                            setSearchScope={setSearchScope}
                          />
                        </InputAdornment>
                      ),
                    },
                  }}
                />
              )}
              renderOption={(propsOption, option) => (
                <li {...propsOption}>
                  <div style={{ display: 'inline-block', paddingTop: 4 }}>
                    <ItemIcon type={option.type} color={option.color} />
                  </div>
                  <div style={{ display: 'inline-block', marginLeft: 10 }}>
                    {option.label}
                  </div>
                </li>
              )}
            />
          ) : isVocabulary ? (
            <Autocomplete
              size="small"
              fullWidth
              openOnFocus
              options={vocabOptions}
              value={selectedVocabOption}
              inputValue={vocabInputValue}
              getOptionLabel={(option) => option.label ?? ''}
              isOptionEqualToValue={(option, val) => option.value === val.value}
              noOptionsText={t_i18n('No available options')}
              onOpen={() => loadVocabularyOptions('')}
              onFocus={() => loadVocabularyOptions('')}
              onInputChange={(_event, newInputValue, reason) => {
                setVocabInputValue(newInputValue);
                if (reason === 'input') {
                  loadVocabularyOptions(newInputValue);
                }
                if (reason === 'clear') {
                  setInputValue('');
                }
              }}
              onChange={(_event, option) => {
                setInputValue(option?.value ?? '');
                setVocabInputValue(option?.label ?? '');
              }}
              renderInput={(params) => (
                <TextField
                  {...params}
                  placeholder={t_i18n('Select a value')}
                  variant="outlined"
                  size="small"
                  fullWidth
                  slotProps={{
                    input: {
                      ...params.InputProps,
                      endAdornment: inputValue ? (
                        <InputAdornment position="end">
                          <IconButton size="small" onClick={() => { setInputValue(''); setVocabInputValue(''); }}>
                            <CloseOutlined fontSize="small" />
                          </IconButton>
                        </InputAdornment>
                      ) : params.InputProps.endAdornment,
                    },
                  }}
                />
              )}
            />
          ) : isBoolean ? (
            <FormControl fullWidth size="small">
              <InputLabel>{t_i18n('Variable value')}</InputLabel>
              <Select
                value={inputValue}
                label={t_i18n('Variable value')}
                onChange={(event) => setInputValue(event.target.value)}
              >
                <MenuItem value="">{t_i18n('No value')}</MenuItem>
                <MenuItem value="true">true</MenuItem>
                <MenuItem value="false">false</MenuItem>
              </Select>
            </FormControl>
          ) : (
            <TextField
              fullWidth
              size="small"
              placeholder={t_i18n('Enter a value')}
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') handleApply(); }}
              InputProps={{
                endAdornment: inputValue ? (
                  <IconButton size="small" onClick={() => setInputValue('')}>
                    <CloseOutlined fontSize="small" />
                  </IconButton>
                ) : undefined,
              }}
            />
          )}
          <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1, mt: 1 }}>
            <Tooltip title={t_i18n('Delete variable')}>
              <IconButton size="small" color="error" onClick={handleDeleteVariable}>
                <DeleteOutlined fontSize="small" />
              </IconButton>
            </Tooltip>
            <Button size="small" onClick={handleReset} disabled={!isOverridden}>{t_i18n('Reset to default')}</Button>
            {!isEntityRef && (
              <Button size="small" variant="contained" onClick={handleApply}>
                {t_i18n('Apply')}
              </Button>
            )}
          </Box>
        </Box>
      </Popover>
    </>
  );
};

export default VariableValueControl;



