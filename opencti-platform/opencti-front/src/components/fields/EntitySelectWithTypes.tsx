import { Combobox, ComboboxClear, ComboboxContent, ComboboxControls, ComboboxField, ComboboxInput, ComboboxLabel, ComboboxTrigger } from '@filigran/design-system';
import Tooltip from '@mui/material/Tooltip';
import React, { FunctionComponent, useState, SyntheticEvent } from 'react';
import SearchScopeElement from '@components/common/lists/SearchScopeElement';
import ItemIcon from '../ItemIcon';
import { useFormatter } from '../i18n';
import useSearchEntities, { EntityValue } from '../../utils/filters/useSearchEntities';
import { getOptionsFromEntities } from '../../utils/filters/SearchEntitiesUtil';

interface EntitySelectWithTypesProps {
  label?: string;
  handleChange: (value: EntityValue) => void;
  value: EntityValue | null;
  entitiesToExclude: string[];
  disabled?: boolean;
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
    .filter((option) => option.value === null || !entitiesToExclude.includes(option.value));

  return (
    <Combobox<EntityValue>
      disabled={disabled}
      className="w-full"
      getOptionLabel={(option) => option.label ?? ''}
      options={options}
      value={value}
      groupBy={(option) => t_i18n(option?.group ? option?.group : label)}
      onInputChange={(_, meta) => searchEntities('id', cacheEntities, setCacheEntities, meta.event as SyntheticEvent)}
      isOptionEqualToValue={(option, val) => option.value === val.value}
      onValueChange={(next) => handleChange(next as EntityValue)}
      renderOption={(option) => (
        <Tooltip title={option.label} followCursor>
          <span style={{ display: 'flex', alignItems: 'center', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            <ItemIcon type={option.type} color={option.color} />
            <span style={{ margin: 6, padding: '0 4px 0 4px' }}>{option.label}</span>
          </span>
        </Tooltip>
      )}
    >
      <ComboboxLabel>{label}</ComboboxLabel>
      <ComboboxField
        // #155: the two slots that replace MUI's input adornments. The icon of
        // the selected value is presentational and goes to startIcon; the search
        // scope control is interactive and goes to adornment, the one host-owned
        // slot on this line that keeps its own pointer and focus behaviour.
        startIcon={value ? <ItemIcon type={value.type} color={value.color} /> : undefined}
        adornment={(
          <SearchScopeElement
            name="id"
            disabled={disabled}
            searchScope={searchScope}
            setSearchScope={setSearchScope}
            availableRelationFilterTypes={undefined}
          />
        )}
      >
        <ComboboxInput
          onFocus={(event) => searchEntities('id', cacheEntities, setCacheEntities, event)}
        />
        <ComboboxControls>
          <ComboboxClear />
          <ComboboxTrigger />
        </ComboboxControls>
      </ComboboxField>
      <ComboboxContent emptyMessage={t_i18n('No available options')} listAriaLabel={label} />
    </Combobox>
  );
};

export default EntitySelectWithTypes;
