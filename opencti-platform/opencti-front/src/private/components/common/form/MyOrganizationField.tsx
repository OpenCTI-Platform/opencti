import React from 'react';
import { Field } from 'formik';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import useAuth from '../../../../utils/hooks/useAuth';

export interface OrganizationOption {
  value: string;
  label: string ;
}

interface MyOrganizationFieldProps {
  name: string;
  label: string;
  disabled:boolean;
  multiple:boolean;
  style:any;
  onChange:any;
}

const MyOrganizationField = (props: MyOrganizationFieldProps) => {
  const {
    name,
    label,
    disabled,
    multiple = true,
    style,
    onChange,
  } = props;
  const { t_i18n } = useFormatter();
  const { me } = useAuth();
  const myOrganizationList: OrganizationOption[] = [];
  if (me.objectOrganization) {
    for (let i = 0; i < me.objectOrganization?.edges.length; i += 1) {
      const org = me.objectOrganization?.edges[i];
      myOrganizationList.push({ value: org?.node.id, label: org?.node.name });
    }
  }
  return (
    <Field
      component={AutocompleteField}
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
      onChange={typeof onChange === 'function' ? onChange : null}
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
