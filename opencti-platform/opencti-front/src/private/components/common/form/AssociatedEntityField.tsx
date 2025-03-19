import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { Autocomplete, TextField } from '@mui/material';
import { AssociatedEntityFieldQuery$data } from './__generated__/AssociatedEntityFieldQuery.graphql';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';

interface AssociatedEntityFieldProps {
  name: string;
  label: string;
  onChange?: (name: string, value: AssociatedEntityOption) => void;
}

export interface AssociatedEntityOption {
  label: string;
  value: string;
  type: string;
}

export const associatedEntityFieldQuery = graphql`
  query AssociatedEntityFieldQuery(
    $search: String
    $types: [String]
  ) {
    stixCoreObjects(
      search: $search
      types: $types
    ) {
      edges {
        node {
          id
          entity_type
          parent_types
          representative {
              main
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
        }
      }
    }
  }
`;

const AssociatedEntityField: FunctionComponent<AssociatedEntityFieldProps> = ({
  name,
  label,
  onChange,
}) => {
  const { t_i18n } = useFormatter();
  const [associatedEntities, setAssociatedEntities] = useState<AssociatedEntityOption[]>([]);
  const [inputValue, setInputValue] = useState<string>('');
  const [value, setValue] = useState<AssociatedEntityOption | null>(null);

  const searchAssociatedEntities = (event: React.SyntheticEvent, newValue?: string) => {
    if (!event) return;
    setInputValue(newValue || '');
    fetchQuery(associatedEntityFieldQuery, {
      search: newValue ?? '',
      types: [],
    })
      .toPromise()
      .then((data) => {
        const { stixCoreObjects } = data as AssociatedEntityFieldQuery$data;
        const elements = stixCoreObjects?.edges.map((e) => e.node);
        if (elements) {
          const newAssociatedEntities = elements.map((n) => ({
            label: n.representative.main,
            type: n.entity_type,
            value: n.id,
          }))
            .sort((a, b) => a.label.localeCompare(b.label))
            .sort((a, b) => a.type.localeCompare(b.type));
          setAssociatedEntities(newAssociatedEntities);
        } else {
          setAssociatedEntities([]);
        }
      });
  };

  const handleChangeSelectedValue = (event: React.SyntheticEvent, newSelectedValue: AssociatedEntityOption | null) => {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    setValue(newSelectedValue);
    onChange?.(name, newSelectedValue || { label: '', value: '', type: '' });
  };

  return (
    <Autocomplete
      size="small"
      fullWidth={true}
      selectOnFocus={true}
      autoHighlight={true}
      getOptionLabel={(option) => (option.label ?? '')}
      value={value ?? undefined}
      multiple={false}
      renderInput={(params) => (
        <TextField
          {...params}
          name={name}
          variant="standard"
          label={label}
          fullWidth={true}
          onFocus={searchAssociatedEntities}
          style={{ marginTop: 3 }}
        />
      )}
      noOptionsText={t_i18n('No available options')}
      options={associatedEntities}
      onInputChange={searchAssociatedEntities}
      inputValue={inputValue || ''}
      onChange={handleChangeSelectedValue}
      isOptionEqualToValue={(option, val) => { return option.value === val.value; }}
      renderOption={(props, option) => (
        <li {...props}>
          <div style={{ paddingTop: 4, display: 'inline-block' }}>
            <ItemIcon type={option.type} />
          </div>
          <div style={{ display: 'inline-block', flexGrow: 1, marginLeft: 10 }}>{option.label}</div>
        </li>
      )}
    />
  );
};

export default AssociatedEntityField;
