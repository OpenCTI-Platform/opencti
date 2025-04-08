import React, { CSSProperties } from 'react';
import { Field } from 'formik';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import useAuth from '../../../../utils/hooks/useAuth';
import { FieldOption } from '../../../../utils/field';

interface MyOrganizationFieldProps {
  name: string;
  label: string;
  disabled:boolean;
  multiple:boolean;
  style?: CSSProperties;
  onChange?: (name: string, value: FieldOption) => void;
}

const MyOrganizationField = (props: MyOrganizationFieldProps) => {
  const {
    name,
    label,
    disabled,
    multiple = true,
    style = {},
    onChange = null,
  } = props;
  const { t_i18n } = useFormatter();
  const { me } = useAuth();
  const myOrganizationList: FieldOption[] = [];
  if (me.objectOrganization) {
    for (let i = 0; i < me.objectOrganization?.edges.length; i += 1) {
      const org = me.objectOrganization?.edges[i];
      myOrganizationList.push({ value: org?.node.id, label: org?.node.name });
    }
  }
  return (
    <Field
      component={AutocompleteField}
      required
      name={name}
      multiple={multiple}
      disabled={disabled}
      style={style}
      textfieldprops={{
        variant: 'standard',
        label: t_i18n(label) ?? '',
      }}
      noOptionsText={t_i18n('No available options')}
      options={myOrganizationList}
      onChange={onChange}
      renderOption={(
        renderProps: React.HTMLAttributes<HTMLLIElement>,
        option: { value: string; label: string },
      ) => (
        <li {...renderProps}>
          <div style={{ paddingTop: 4, display: 'inline-block' }}>
            <ItemIcon type="Organization"/>
          </div>
          <div style={{ display: 'inline-block', flexGrow: 1, marginLeft: 10 }}>{option.label ?? ''}</div>
        </li>
      )}
    />
  );
};

export default MyOrganizationField;
