import { graphql } from 'react-relay';
import React, { CSSProperties, useState } from 'react';
import { Field } from 'formik';
import { PirFieldQuery$data } from './__generated__/PirFieldQuery.graphql';
import { FieldOption } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';
import { ComboboxChangeMeta } from '@filigran/design-system';
import ComboboxField from '../../../../components/ComboboxField';
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

  const searchPirs = async (search: string) => {
    const data = await fetchQuery(
      pirsQuery,
      { search, first: 50 },
    ).toPromise() as PirFieldQuery$data;

    setPirs((data?.pirs?.edges ?? []).flatMap((n) => (!n ? [] : {
      label: n.node.name,
      value: n.node.id,
      type: n.node.entity_type,
    })));
  };

  return (
    <Field
      component={ComboboxField}
      style={style}
      name={name}
      multiple={multiple}
      disabled={disabled}
      required={required}
      label={label ?? t_i18n('PIR')}
      helperText={helpertext}
      noOptionsText={t_i18n('No available options')}
      options={pirs}
      // Fires on the keystroke only: `select`, `clear` and `reset` reach this
      // callback too, and querying on them is the bug the pre-library sites
      // guarded against by testing for a DOM event.
      onInputChange={(search: string, meta: ComboboxChangeMeta) => {
        if (meta.cause === 'type') searchPirs(search);
      }}
      onFocusInput={() => searchPirs('')}
      onChange={onChange}
      renderOption={(option: FieldOption) => (
        <>
          <div style={{ paddingTop: 4, display: 'inline-block' }}>
            <ItemIcon type="pir" />
          </div>
          <div style={{
            display: 'inline-block',
            flexGrow: 1,
            marginLeft: 10,
          }}
          >{option.label}
          </div>
        </>
      )}
    />
  );
};

export default PirField;
