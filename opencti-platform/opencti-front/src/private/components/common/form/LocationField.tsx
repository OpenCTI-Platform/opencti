import { graphql } from 'react-relay';
import React, { ChangeEvent, HTMLAttributes, useState } from 'react';
import { Field } from 'formik';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import EntityTypeSelectAdornment from '@components/common/form/EntityTypeSelectAdornment';
import { useFormatter } from '../../../../components/i18n';
import { FieldOption } from '../../../../utils/field';
import { fetchQuery } from '../../../../relay/environment';
import { LocationFieldSearchQuery$data } from './__generated__/LocationFieldSearchQuery.graphql';
import AutocompleteField from '../../../../components/AutocompleteField';
import ItemIcon from '../../../../components/ItemIcon';

const locationFieldSearchQuery = graphql`
  query LocationFieldSearchQuery($search: String, $types: [String]) {
    locations(search: $search, types: $types, orderBy: name) {
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

interface LocationFieldProps {
  name: string;
  label: string;
  containerStyle?: Record<string, string | number>;
  helperText?: string;
  required?: boolean;
}

const LocationField = ({
  name,
  label,
  containerStyle,
  helperText,
  required,
}: LocationFieldProps) => {
  const { t_i18n } = useFormatter();
  const [options, setOptions] = useState<FieldOption[]>([]);
  const [types, setTypes] = useState<string[]>([]);

  const searchLocations = async (e: ChangeEvent<HTMLInputElement>) => {
    const search = e && e.target.value ? e.target.value : '';
    const { locations } = (await fetchQuery(
      locationFieldSearchQuery,
      { search, types },
    ).toPromise()) as LocationFieldSearchQuery$data;
    setOptions((locations?.edges ?? []).flatMap((edge) => {
      if (!edge) return [];
      return {
        label: edge.node.name,
        value: edge.node.id,
        type: edge.node.entity_type,
      };
    }).sort((a, b) => a.type.localeCompare(b.type)));
  };

  return (
    <Field
      component={AutocompleteField}
      groupBy={(option: FieldOption) => option.type}
      multiple
      name={name}
      required={required}
      textfieldprops={{
        variant: 'standard',
        label,
        helperText,
        onFocus: searchLocations,
        required,
      }}
      style={containerStyle}
      noOptionsText={t_i18n('No available options')}
      options={options}
      onInputChange={searchLocations}
      endAdornment={(
        <EntityTypeSelectAdornment
          value={types}
          onChange={setTypes}
          entityTypes={['Region', 'Country', 'Administrative-Area', 'City', 'Position']}
        />
      )}
      renderOption={(
        props: HTMLAttributes<HTMLLIElement>,
        option: FieldOption,
      ) => (
        <ListItem {...props}>
          <ItemIcon type={option.type} />
          <ListItemText primary={option.label} sx={{ marginLeft: 2 }}/>
        </ListItem>
      )}
    />
  );
};

export default LocationField;
