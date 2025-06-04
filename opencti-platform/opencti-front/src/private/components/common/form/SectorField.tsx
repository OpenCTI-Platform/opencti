import { graphql } from 'react-relay';
import React, { ChangeEvent, HTMLAttributes, useState } from 'react';
import { Field } from 'formik';
import ListItemText from '@mui/material/ListItemText';
import ListItem from '@mui/material/ListItem';
import { useFormatter } from '../../../../components/i18n';
import { FieldOption } from '../../../../utils/field';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { SectorFieldSearchQuery$data } from './__generated__/SectorFieldSearchQuery.graphql';
import ItemIcon from '../../../../components/ItemIcon';

const sectorFieldSearchQuery = graphql`
  query SectorFieldSearchQuery($search: String) {
    sectors(search: $search, orderBy: name) {
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

interface SectorFieldProps {
  name: string;
  label: string;
  containerStyle?: Record<string, string | number>;
  helperText?: string;
  required?: boolean;
}

const SectorField = ({
  name,
  label,
  containerStyle,
  helperText,
  required,
}: SectorFieldProps) => {
  const { t_i18n } = useFormatter();
  const [options, setOptions] = useState<FieldOption[]>([]);

  const searchSectors = async (e: ChangeEvent<HTMLInputElement>) => {
    const search = e && e.target.value ? e.target.value : '';
    const { sectors } = (await fetchQuery(
      sectorFieldSearchQuery,
      { search },
    ).toPromise()) as SectorFieldSearchQuery$data;
    setOptions((sectors?.edges ?? []).flatMap((edge) => {
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
        onFocus: searchSectors,
        required,
      }}
      style={containerStyle}
      noOptionsText={t_i18n('No available options')}
      options={options}
      onInputChange={searchSectors}
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

export default SectorField;
