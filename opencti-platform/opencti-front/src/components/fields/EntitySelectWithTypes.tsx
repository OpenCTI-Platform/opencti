import { Autocomplete } from '@mui/material';
import TextField from '@mui/material/TextField';
import Tooltip from '@mui/material/Tooltip';
import React, { Dispatch, FunctionComponent, SyntheticEvent, useState } from 'react';
import { OptionValue } from '@components/common/lists/FilterAutocomplete';
import SearchScopeElement from '@components/common/lists/SearchScopeElement';
import ItemIcon from '../ItemIcon';
import { useFormatter } from '../i18n';
import useSearchEntities from '../../utils/filters/useSearchEntities';
import { getOptionsFromEntities } from '../../utils/filters/SearchEntitiesUtil';

interface EntitySelectWithTypesProps {
  label?: string,
  handleChange: (value: string) => void,
  alreadyUsedInstances: string[],
  initialInstance?: { id: string, entity_type: string, representative: { main: string } } | null,
}

const EntitySelectWithTypes: FunctionComponent<EntitySelectWithTypesProps> = ({
  label,
  handleChange,
  alreadyUsedInstances,
  initialInstance,
}) => {
  const { t_i18n } = useFormatter();

  const groupByEntities = (option: OptionValue, optionLabel?: string) => {
    return t_i18n(option?.group ? option?.group : optionLabel);
  };
  const [searchScope, setSearchScope] = useState<Record<string, string[]>>(
    {
      targets: [
        'Region',
        'Country',
        'Administrative-Area',
        'City',
        'Position',
        'Sector',
        'Organization',
        'Individual',
        'System',
        'Event',
        'Vulnerability',
      ],
    },
  );
  const [cacheEntities, setCacheEntities] = useState<Record<string, OptionValue[]>>({});

  const [entities, searchEntities] = useSearchEntities({
    setInputValues: () => {},
    searchContext: { entityTypes: ['Stix-Core-Object'] },
    searchScope: { entityTypes: ['Stix-Core-Object'] },
  }) as [Record<string, OptionValue[]>, (
    filterKey: string,
    cacheEntities: Record<string, OptionValue[]>,
    setCacheEntities: Dispatch<Record<string, OptionValue[]>>,
    event: SyntheticEvent,
  ) => Record<string, OptionValue[]>,
  ];
  let options = getOptionsFromEntities(entities, searchScope, 'id')
    .filter((option) => !alreadyUsedInstances.includes(option.value));
  if (initialInstance) {
    const initialOption = {
      value: initialInstance.id,
      label: initialInstance.representative.main,
      type: initialInstance.entity_type,
      parentTypes: [],
    };
    options = [initialOption, ...options];
  }

  const renderSearchScopeSelection = () => {
    return (
      <SearchScopeElement
        name={'id'}
        searchScope={searchScope}
        setSearchScope={setSearchScope}
        availableRelationFilterTypes={undefined}
      />
    );
  };
  return (
    <Autocomplete
      key={'id'}
      getOptionLabel={(option) => option.label ?? ''}
      noOptionsText={t_i18n('No available options')}
      options={options}
      groupBy={(option) => groupByEntities(option, label)}
      onInputChange={(event) => searchEntities('id', cacheEntities, setCacheEntities, event)}
      renderInput={(paramsInput) => (
        <TextField
          {...paramsInput}
          InputProps={{
            ...paramsInput.InputProps,
            endAdornment: renderSearchScopeSelection(),
          }}
          label={initialInstance
            ? <>
              <ItemIcon type={initialInstance.entity_type} />
              <span style={{ padding: '0 0 0 4px' }}>
                {initialInstance.representative.main}
              </span></>
            : label}
          variant="outlined"
          size="small"
          fullWidth={true}
          onFocus={(event) => searchEntities(
            'id',
            cacheEntities,
            setCacheEntities,
            event,
          )
          }
        />
      )}
      renderOption={(props, option) => {
        return (
          <Tooltip title={option.label} key={option.label} followCursor>
            <li
              {...props}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.stopPropagation();
                }
              }}
              onClick={() => handleChange(option.value)}
              style={{
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                margin: 0,
              }}
            >
              <ItemIcon type={option.type} color={option.color} />
              <span style={{ margin: 6, padding: '0 4px 0 4px' }}>
                {option.label}
              </span>
            </li>
          </Tooltip>
        );
      }}
    />
  );
};

export default EntitySelectWithTypes;
