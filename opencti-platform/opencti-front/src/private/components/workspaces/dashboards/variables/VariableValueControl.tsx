import React, { Dispatch, Suspense, SyntheticEvent, useEffect, useMemo, useState } from 'react';
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
import DatePicker from '@common/input/DatePicker';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../../components/i18n';
import { fetchQuery } from '../../../../../relay/environment';
import type { VariableValueControlEntityLabelQuery } from './__generated__/VariableValueControlEntityLabelQuery.graphql';
import useSearchEntities from '../../../../../utils/filters/useSearchEntities';
import SearchScopeElement from '../../../common/lists/SearchScopeElement';
import { FilterOptionValue } from '../../../common/lists/FilterAutocomplete';
import ItemIcon from '../../../../../components/ItemIcon';
import { useDashboardVariables } from './DashboardVariablesContext';
import { vocabularySearchQuery } from '../../../settings/VocabularyQuery';
import { labelsSearchQuery } from '../../../settings/LabelsQuery';
import { markingDefinitionsLinesSearchQuery } from '../../../settings/MarkingDefinitionsQuery';
import { identitySearchCreatorsSearchQuery } from '../../../common/identities/IdentitySearch';
import { statusFieldStatusesSearchQuery } from '../../../common/form/StatusField';
import { killChainPhasesSearchQuery } from '../../../settings/KillChainPhases';
import { buildDate, parse } from '../../../../../utils/Time';

interface BackendFilterGroup {
  mode: string;
  filters: Array<{ key: string[]; values: string[]; operator: string; mode: string }>;
  filterGroups: BackendFilterGroup[];
}

const groupsSearchQuery = graphql`
  query VariableValueControlGroupsSearchQuery($search: String) {
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
  query VariableValueControlEntityRestrictionSearchQuery($filters: FilterGroup, $search: String, $count: Int) {
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

/** Resolves the display label via filtersRepresentatives. Falls back to '(not set)' when the entity no longer resolves. */
const EntityRefLabel: React.FC<{ entityId: string }> = ({ entityId }) => {
  const { t_i18n } = useFormatter();
  const data = useLazyLoadQuery<VariableValueControlEntityLabelQuery>(
    entityLabelQuery,
    {
      filters: {
        mode: 'and',
        filters: [{ key: ['ids'], values: [entityId], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
    },
    { fetchPolicy: 'store-or-network' },
  );
  const label = data.filtersRepresentatives?.[0]?.value;
  return <>{label ?? t_i18n('(not set)')}</>;
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
  restrictionMode?: string | null;
  restrictionValues?: ReadonlyArray<string> | null;
  restrictionFilters?: string | null;
  onVariableDeleted?: (variableId: string) => void;
}

interface VocabOption {
  label: string;
  value: string;
  categoryKey?: string;
}

interface SimpleOption {
  label: string;
  value: string;
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
  restrictionMode,
  restrictionValues,
  restrictionFilters,
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
  const [vocabOptions, setVocabOptions] = useState<VocabOption[]>([]);
  const [vocabInputValue, setVocabInputValue] = useState('');
  const [simpleInputValue, setSimpleInputValue] = useState('');
  const [labelOptions, setLabelOptions] = useState<SimpleOption[]>([]);
  const [userOptions, setUserOptions] = useState<SimpleOption[]>([]);
  const [markingOptions, setMarkingOptions] = useState<SimpleOption[]>([]);
  const [statusOptions, setStatusOptions] = useState<SimpleOption[]>([]);
  const [killChainOptions, setKillChainOptions] = useState<SimpleOption[]>([]);
  const [groupOptions, setGroupOptions] = useState<SimpleOption[]>([]);
  const [entityRestrictionOptions, setEntityRestrictionOptions] = useState<FilterOptionValue[]>([]);
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

  const effectiveValue = currentValue ?? defaultValue;
  const isOverridden = currentValue !== null && currentValue !== undefined;
  const isVocabulary = filterKeyType === 'vocabulary';

  const handleOpen = (event: React.MouseEvent<HTMLElement>) => {
    setInputValue(currentValue ?? defaultValue ?? '');
    setEntityDraftValue(selectedEntityOption);
    setEntityInputValue(selectedEntityOption?.label ?? '');
    setVocabInputValue(currentValue ?? defaultValue ?? '');
    setSimpleInputValue(selectedSimpleOption?.label ?? currentValue ?? defaultValue ?? '');
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
  const isLabel = filterKeyType === 'label';
  const isUser = filterKeyType === 'user';
  const isMarking = filterKeyType === 'marking';
  const isStatus = filterKeyType === 'status';
  const isGroup = filterKeyType === 'group';
  const isDate = filterKeyType === 'date';
  const isEntityRestricted = isEntityRef && (restrictionMode === 'filter' || restrictionMode === 'manual');
  const displayValue = effectiveValue ?? t_i18n('(not set)');
  const isHighlighted = isUsedInWidgets;
  const variableTypeLabel = (() => {
    switch (filterKeyType) {
      case 'entity_ref': return t_i18n('Entity selector');
      case 'boolean': return t_i18n('Boolean');
      case 'vocabulary': return t_i18n('Vocabulary');
      case 'numeric': return t_i18n('Number');
      case 'kill_chain': return t_i18n('Kill chain phase');
      case 'text': return t_i18n('Text');
      case 'label': return t_i18n('Label');
      case 'user': return t_i18n('User');
      case 'marking': return t_i18n('Marking');
      case 'status': return t_i18n('Status');
      case 'date': return t_i18n('Date');
      case 'group': return t_i18n('Group');
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
          ? [{ key: ['ids'], values: [effectiveValue], operator: 'eq', mode: 'or' }]
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
        <Suspense fallback={<>{t_i18n('(not set)')}</>}>
          <EntityRefLabel entityId={effectiveValue} />
        </Suspense>
      ) : (isLabel || isMarking || isStatus || isKillChain || isGroup) && effectiveValue ? (
        (labelOptions.concat(markingOptions, statusOptions, killChainOptions, groupOptions).find((o) => o.value === effectiveValue)?.label ?? t_i18n('(not set)'))
      ) : isUser && effectiveValue ? (
        (userOptions.find((o) => o.value === effectiveValue)?.label ?? t_i18n('(not set)'))
      ) : isDate && effectiveValue ? (
        parse(effectiveValue).format('YYYY-MM-DD')
      ) : displayValue}
    </>
  );

  const entityOptions: FilterOptionValue[] = searchScope[ENTITY_REF_FILTER_KEY]?.length > 0
    ? (entities[ENTITY_REF_FILTER_KEY] ?? []).filter((n) => searchScope[ENTITY_REF_FILTER_KEY].some((s) => (n.parentTypes ?? []).concat(n.type).includes(s)))
    : (entities[ENTITY_REF_FILTER_KEY] ?? []);

  const selectedEntityOption = useMemo<FilterOptionValue | null>(() => {
    if (!isEntityRef || !effectiveValue) return null;
    const options = isEntityRestricted ? entityRestrictionOptions : entityOptions;
    const selectedInOptions = options.find((option) => option.value === effectiveValue);
    if (selectedInOptions) return selectedInOptions;
    const resolvedLabel = entityLabelData.filtersRepresentatives?.[0]?.value;
    if (!resolvedLabel) return null;
    return {
      value: effectiveValue,
      label: resolvedLabel,
      type: 'Stix-Core-Object',
    };
  }, [isEntityRef, isEntityRestricted, effectiveValue, entityOptions, entityRestrictionOptions, entityLabelData.filtersRepresentatives]);

  const buildEntityRestrictionFilters = (): BackendFilterGroup | null => {
    if (restrictionMode === 'manual' && restrictionValues && restrictionValues.length > 0) {
      return { mode: 'and', filters: [{ key: ['ids'], values: [...restrictionValues], operator: 'eq', mode: 'or' }], filterGroups: [] };
    }
    if (restrictionMode === 'filter' && restrictionFilters) {
      try {
        return JSON.parse(restrictionFilters) as BackendFilterGroup;
      } catch {
        return null;
      }
    }
    return null;
  };

  const loadEntityRestrictionOptions = (search = '') => {
    fetchQuery(entityRestrictionSearchQuery, {
      filters: buildEntityRestrictionFilters(),
      search,
      count: 50,
    }).toPromise().then((data: any) => {
      const options: FilterOptionValue[] = (data?.stixCoreObjects?.edges ?? []).map((edge: any) => ({
        label: edge.node.representative?.main ?? edge.node.id,
        value: edge.node.id,
        type: edge.node.entity_type,
      }));
      setEntityRestrictionOptions(options);
    });
  };

  const selectedVocabOption = useMemo<VocabOption | null>(() => {
    if (!isVocabulary || !effectiveValue) return null;
    const existing = vocabOptions.find((option) => option.value === effectiveValue);
    if (existing) return existing;
    return { label: effectiveValue, value: effectiveValue };
  }, [effectiveValue, isVocabulary, vocabOptions]);

  const vocabSelectableOptions = restrictionMode === 'restricted' && restrictionValues && restrictionValues.length > 0
    ? vocabOptions.filter((option) => restrictionValues.includes(option.value))
    : vocabOptions;

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

  const loadLabelOptions = (search = '') => {
    fetchQuery(labelsSearchQuery, { search }).toPromise().then((data: any) => {
      const options: SimpleOption[] = (data?.labels?.edges ?? []).map((edge: any) => ({
        label: edge.node.value,
        value: edge.node.id,
        color: edge.node.color,
      }));
      setLabelOptions(options);
    });
  };

  const loadUserOptions = (search = '') => {
    fetchQuery(identitySearchCreatorsSearchQuery, { entityTypes: ['User'] }).toPromise().then((data: any) => {
      const options: SimpleOption[] = (data?.creators?.edges ?? [])
        .map((edge: any) => ({ label: edge.node.name, value: edge.node.id }))
        .filter((o: SimpleOption) => o.label.toLowerCase().includes(search.toLowerCase()));
      setUserOptions(options);
    });
  };

  const loadMarkingOptions = (search = '') => {
    fetchQuery(markingDefinitionsLinesSearchQuery, { search }).toPromise().then((data: any) => {
      const options: SimpleOption[] = (data?.markingDefinitions?.edges ?? []).map((edge: any) => ({
        label: edge.node.definition,
        value: edge.node.id,
        color: edge.node.x_opencti_color,
      }));
      setMarkingOptions(options);
    });
  };

  const loadStatusOptions = (search = '') => {
    fetchQuery(statusFieldStatusesSearchQuery, {
      first: 100,
      filters: null,
      orderBy: 'order',
      orderMode: 'asc',
      search,
    }).toPromise().then((data: any) => {
      const options: SimpleOption[] = (data?.statuses?.edges ?? [])
        .filter((edge: any) => edge?.node?.template)
        .map((edge: any) => ({
          label: `${edge.node.template.name} (${edge.node.type})`,
          value: edge.node.id,
          color: edge.node.template.color,
        }));
      setStatusOptions(options);
    });
  };

  const loadKillChainOptions = (search = '') => {
    fetchQuery(killChainPhasesSearchQuery, { search }).toPromise().then((data: any) => {
      const options: SimpleOption[] = (data?.killChainPhases?.edges ?? [])
        .filter((edge: any) => !filterKey || edge.node.kill_chain_name === filterKey)
        .map((edge: any) => ({ label: edge.node.phase_name, value: edge.node.id }));
      setKillChainOptions(options);
    });
  };

  const loadGroupOptions = (search = '') => {
    fetchQuery(groupsSearchQuery, { search }).toPromise().then((data: any) => {
      const options: SimpleOption[] = (data?.groups?.edges ?? []).map((edge: any) => ({
        label: edge.node.name,
        value: edge.node.id,
      }));
      setGroupOptions(options);
    });
  };

  // Resolve the current value's label eagerly, so the chip doesn't display a raw id
  // until the user happens to open the popover (which is what normally triggers the load).
  useEffect(() => {
    if (!effectiveValue) return;
    if (isLabel && labelOptions.length === 0) loadLabelOptions('');
    if (isUser && userOptions.length === 0) loadUserOptions('');
    if (isMarking && markingOptions.length === 0) loadMarkingOptions('');
    if (isStatus && statusOptions.length === 0) loadStatusOptions('');
    if (isKillChain && killChainOptions.length === 0) loadKillChainOptions('');
    if (isGroup && groupOptions.length === 0) loadGroupOptions('');
  }, [effectiveValue, filterKeyType]);

  const selectedLabelOption = useMemo<SimpleOption | null>(() => {
    if (!isLabel || !effectiveValue) return null;
    return labelOptions.find((option) => option.value === effectiveValue) ?? { label: effectiveValue, value: effectiveValue };
  }, [effectiveValue, isLabel, labelOptions]);

  const selectedUserOption = useMemo<SimpleOption | null>(() => {
    if (!isUser || !effectiveValue) return null;
    return userOptions.find((option) => option.value === effectiveValue) ?? { label: effectiveValue, value: effectiveValue };
  }, [effectiveValue, isUser, userOptions]);

  const selectedMarkingOption = useMemo<SimpleOption | null>(() => {
    if (!isMarking || !effectiveValue) return null;
    return markingOptions.find((option) => option.value === effectiveValue) ?? { label: effectiveValue, value: effectiveValue };
  }, [effectiveValue, isMarking, markingOptions]);

  const selectedStatusOption = useMemo<SimpleOption | null>(() => {
    if (!isStatus || !effectiveValue) return null;
    return statusOptions.find((option) => option.value === effectiveValue) ?? { label: effectiveValue, value: effectiveValue };
  }, [effectiveValue, isStatus, statusOptions]);

  const selectedKillChainOption = useMemo<SimpleOption | null>(() => {
    if (!isKillChain || !effectiveValue) return null;
    return killChainOptions.find((option) => option.value === effectiveValue) ?? { label: effectiveValue, value: effectiveValue };
  }, [effectiveValue, isKillChain, killChainOptions]);

  const selectedGroupOption = useMemo<SimpleOption | null>(() => {
    if (!isGroup || !effectiveValue) return null;
    return groupOptions.find((option) => option.value === effectiveValue) ?? { label: effectiveValue, value: effectiveValue };
  }, [effectiveValue, isGroup, groupOptions]);

  const rawSimpleSelectOptions = isLabel ? labelOptions
    : isUser ? userOptions
      : isMarking ? markingOptions
        : isKillChain ? killChainOptions
          : isGroup ? groupOptions
            : statusOptions;
  const simpleSelectOptions = restrictionMode === 'restricted' && restrictionValues && restrictionValues.length > 0
    ? rawSimpleSelectOptions.filter((option) => restrictionValues.includes(option.value))
    : rawSimpleSelectOptions;
  const selectedSimpleOption = isLabel ? selectedLabelOption
    : isUser ? selectedUserOption
      : isMarking ? selectedMarkingOption
        : isKillChain ? selectedKillChainOption
          : isGroup ? selectedGroupOption
            : selectedStatusOption;
  const loadSimpleOptions = isLabel ? loadLabelOptions
    : isUser ? loadUserOptions
      : isMarking ? loadMarkingOptions
        : isKillChain ? loadKillChainOptions
          : isGroup ? loadGroupOptions
            : loadStatusOptions;

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
          {isEntityRef && !isEntityRestricted ? (
            <Autocomplete
              size="small"
              fullWidth
              openOnFocus
              forcePopupIcon={false}
              open={entityAutocompleteOpen}
              onOpen={() => setEntityAutocompleteOpen(true)}
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
                searchEntities(ENTITY_REF_FILTER_KEY, cacheEntities, setCacheEntities, event);
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
                searchEntities(ENTITY_REF_FILTER_KEY, cacheEntities, setCacheEntities, event);
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
          ) : isEntityRef && isEntityRestricted ? (
            <Autocomplete
              size="small"
              fullWidth
              openOnFocus
              options={entityRestrictionOptions}
              value={selectedEntityOption}
              inputValue={simpleInputValue}
              getOptionLabel={(option) => option.label ?? ''}
              isOptionEqualToValue={(option, val) => option.value === val.value}
              noOptionsText={t_i18n('No available options')}
              filterOptions={(x) => x}
              onOpen={() => loadEntityRestrictionOptions('')}
              onFocus={() => loadEntityRestrictionOptions('')}
              onInputChange={(_event, newInputValue, reason) => {
                setSimpleInputValue(newInputValue);
                if (reason === 'input' || reason === 'clear') {
                  loadEntityRestrictionOptions(newInputValue);
                }
              }}
              onChange={(_event, option) => {
                if (!option) return;
                commitSet({
                  variables: { workspaceId, variableId, value: option.value },
                  onCompleted: () => {
                    setVariableValue(variableId, option.value);
                    handleClose();
                  },
                });
              }}
              renderInput={(params) => (
                <TextField {...params} placeholder={t_i18n('Select a value')} variant="outlined" size="small" fullWidth />
              )}
              renderOption={(propsOption, option) => (
                <li {...propsOption}>
                  <div style={{ display: 'inline-block', paddingTop: 4 }}>
                    <ItemIcon type={option.type} />
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
              options={vocabSelectableOptions}
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
          ) : (isLabel || isUser || isMarking || isStatus || isKillChain || isGroup) ? (
            <Autocomplete
              size="small"
              fullWidth
              openOnFocus
              options={simpleSelectOptions}
              value={selectedSimpleOption}
              inputValue={simpleInputValue}
              getOptionLabel={(option) => option.label ?? ''}
              isOptionEqualToValue={(option, val) => option.value === val.value}
              noOptionsText={t_i18n('No available options')}
              onOpen={() => loadSimpleOptions('')}
              onFocus={() => loadSimpleOptions('')}
              onInputChange={(_event, newInputValue, reason) => {
                setSimpleInputValue(newInputValue);
                if (reason === 'input') {
                  loadSimpleOptions(newInputValue);
                }
                if (reason === 'clear') {
                  setInputValue('');
                }
              }}
              onChange={(_event, option) => {
                setInputValue(option?.value ?? '');
                setSimpleInputValue(option?.label ?? '');
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
                          <IconButton size="small" onClick={() => { setInputValue(''); setSimpleInputValue(''); }}>
                            <CloseOutlined fontSize="small" />
                          </IconButton>
                        </InputAdornment>
                      ) : params.InputProps.endAdornment,
                    },
                  }}
                />
              )}
            />
          ) : isDate ? (
            <DatePicker
              value={buildDate(inputValue || null)}
              onChange={(value, context) => {
                if (context.validationError) return;
                setInputValue(value ? parse(value).format() : '');
              }}
            />
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
