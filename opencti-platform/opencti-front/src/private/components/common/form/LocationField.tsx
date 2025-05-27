import { graphql } from 'react-relay';
import React, { ChangeEvent, useState } from 'react';
import { Field } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import { FieldOption } from '../../../../utils/field';
import { fetchQuery } from '../../../../relay/environment';
import { LocationFieldSearchQuery$data } from './__generated__/LocationFieldSearchQuery.graphql';
import AutocompleteField from '../../../../components/AutocompleteField';

const locationFieldSearchQuery = graphql`
  query LocationFieldSearchQuery($search: String) {
    locations(search: $search, orderBy: name) {
      edges {
        node {
          id
          name
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

  const searchLocations = async (e: ChangeEvent<HTMLInputElement>) => {
    const search = e && e.target.value ? e.target.value : '';
    const { locations } = (await fetchQuery(
      locationFieldSearchQuery,
      { search },
    ).toPromise()) as LocationFieldSearchQuery$data;
    setOptions((locations?.edges ?? []).flatMap((edge) => {
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
        onFocus: searchLocations,
        required,
      }}
      style={containerStyle}
      noOptionsText={t_i18n('No available options')}
      options={options}
      onInputChange={searchLocations}
    />
  );
};

export default LocationField;
