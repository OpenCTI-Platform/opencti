import { Autocomplete } from '@mui/material';
import TextField from '@mui/material/TextField';
import Tooltip from '@mui/material/Tooltip';
import React, { FunctionComponent, useState } from 'react';
import SearchScopeElement from '@components/common/lists/SearchScopeElement';
import ItemIcon from '../ItemIcon';
import { useFormatter } from '../i18n';
import useSearchEntities, { EntityValue } from '../../utils/filters/useSearchEntities';
import { getOptionsFromEntities } from '../../utils/filters/SearchEntitiesUtil';

interface EntitySelectWithTypesProps {
  label?: string,
  handleChange: (value: EntityValue) => void,
  value: EntityValue | null,
  entitiesToExclude: string[],
  disabled?: boolean
}

const EntitySelectWithTypes: FunctionComponent<EntitySelectWithTypesProps> = ({
  label,
  handleChange,
  value,
  entitiesToExclude,
  disabled,
}) => {
  const { t_i18n } = useFormatter();

  const [searchScope, setSearchScope] = useState<Record<string, string[]>>({});
  const [cacheEntities, setCacheEntities] = useState<Record<string, EntityValue[]>>({});

  const [entities, searchEntities] = useSearchEntities({
    setInputValues: () => {},
    searchContext: { entityTypes: ['Stix-Core-Object'] },
    searchScope,
  });

  const options = getOptionsFromEntities(entities, searchScope, 'id')
    .filter((option) => !entitiesToExclude.includes(option.value));

  return (
    <Autocomplete
      disabled={disabled}
      getOptionLabel={(option) => option.label ?? ''}
      noOptionsText={t_i18n('No available options')}
      options={options}
      value={value}
      groupBy={(option) => t_i18n(option?.group ? option?.group : label)}
      onInputChange={(event) => searchEntities('id', cacheEntities, setCacheEntities, event)}
      isOptionEqualToValue={(option, val) => option.value === val.value}
      renderInput={(paramsInput) => (
        <TextField
          {...paramsInput}
          InputProps={{
            ...paramsInput.InputProps,
            sx: { gap: 1 },
            startAdornment: value
              ? <ItemIcon type={value.type} color={value.color} />
              : null,
            endAdornment: (
              <SearchScopeElement
                name={'id'}
                disabled={disabled}
                searchScope={searchScope}
                setSearchScope={setSearchScope}
                availableRelationFilterTypes={undefined}
              />
            ),
          }}
          label={label}
          size="small"
          fullWidth
          onFocus={(event) => searchEntities(
            'id',
            cacheEntities,
            setCacheEntities,
            event,
          )}
        />
      )}
      renderOption={(props, option) => (
        <Tooltip title={option.label} key={option.label} followCursor>
          <li
            {...props}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.stopPropagation();
              }
            }}
            onClick={() => handleChange(option)}
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
      )}
    />
  );
};

export default EntitySelectWithTypes;
