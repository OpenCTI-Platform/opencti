import { graphql } from 'react-relay';
import React, { ChangeEvent, CSSProperties, useState, HTMLAttributes } from 'react';
import { Field } from 'formik';
import { PirFieldQuery$data } from './__generated__/PirFieldQuery.graphql';
import { FieldOption } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';
import AutocompleteField from '../../../../components/AutocompleteField';
import ItemIcon from '../../../../components/ItemIcon';
import { fetchQuery } from '../../../../relay/environment';

const pirsQuery = graphql`
  query PirFieldQuery($search: String, $first: Int) {
    pirs(search: $search, first: $first) {
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

interface PirFieldProps {
  name: string;
  label?: string;
  multiple?: boolean;
  onChange?: (name: string, value: FieldOption[]) => void;
  helpertext?: string;
  disabled?: boolean;
  required?: boolean;
  style?: CSSProperties;
}

const PirField = ({
  name,
  label,
  multiple,
  onChange,
  helpertext,
  disabled,
  required,
  style,
}: PirFieldProps) => {
  const { t_i18n } = useFormatter();
  const [pirs, setPirs] = useState<FieldOption[]>([]);

  const searchPirs = async ({ target }: ChangeEvent<HTMLInputElement>) => {
    const data = await fetchQuery(
      pirsQuery,
      { search: target.value ?? '', first: 50 },
    ).toPromise() as PirFieldQuery$data;

    setPirs((data?.pirs?.edges ?? []).flatMap((n) => (!n ? [] : {
      label: n.node.name,
      value: n.node.id,
      type: n.node.entity_type,
    })));
  };

  return (
    <Field
      component={AutocompleteField}
      style={style}
      name={name}
      multiple={multiple}
      disabled={disabled}
      required={required}
      textfieldprops={{
        variant: 'standard',
        label: label ?? t_i18n('PIR'),
        helperText: helpertext,
        onFocus: searchPirs,
      }}
      noOptionsText={t_i18n('No available options')}
      options={pirs}
      onInputChange={searchPirs}
      onChange={onChange}
      renderOption={(
        renderProps: HTMLAttributes<HTMLLIElement>,
        option: FieldOption,
      ) => (
        <li {...renderProps}>
          <div style={{ paddingTop: 4, display: 'inline-block' }}>
            <ItemIcon type="pir" />
          </div>
          <div style={{
            display: 'inline-block',
            flexGrow: 1,
            marginInlineStart: 10,
          }}
          >{option.label}
          </div>
        </li>
      )}
    />
  );
};

export default PirField;
