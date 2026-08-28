import { graphql } from 'react-relay';
import React, { useState } from 'react';
import { Field } from 'formik';
import { ComboboxChangeMeta } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import { FieldOption } from '../../../../utils/field';
import { fetchQuery } from '../../../../relay/environment';
import ComboboxField from '../../../../components/ComboboxField';
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

  const searchSectors = async (search: string) => {
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
      component={ComboboxField}
      groupBy={(option: FieldOption) => option.type}
      multiple
      name={name}
      required={required}
      label={label}
      helperText={helperText}
      style={containerStyle}
      noOptionsText={t_i18n('No available options')}
      options={options}
      // The query leaves on the keystroke and on nothing else: `select`,
      // `clear` and `reset` all reach this callback too, and firing on them is
      // what the pre-library sites guarded against by testing for a DOM event.
      onInputChange={(search: string, meta: ComboboxChangeMeta) => {
        if (meta.cause === 'type') searchSectors(search);
      }}
      onFocusInput={() => searchSectors('')}
      renderOption={(option: FieldOption) => (
        <>
          <ItemIcon type={option.type} />
          <span style={{ marginLeft: 16 }}>{option.label}</span>
        </>
      )}
    />
  );
};

export default SectorField;
