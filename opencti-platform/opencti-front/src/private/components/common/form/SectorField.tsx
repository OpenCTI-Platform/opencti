import { graphql } from 'react-relay';
import React, { ChangeEvent, useState } from 'react';
import { Field } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import { FieldOption } from '../../../../utils/field';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { SectorFieldSearchQuery$data } from './__generated__/SectorFieldSearchQuery.graphql';

const sectorFieldSearchQuery = graphql`
  query SectorFieldSearchQuery($search: String) {
    sectors(search: $search, orderBy: name) {
      edges {
        node {
          id
          name
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
      };
    }));
  };

  return (
    <Field
      component={AutocompleteField}
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
    />
  );
};

export default SectorField;
