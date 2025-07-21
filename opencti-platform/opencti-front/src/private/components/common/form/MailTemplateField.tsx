import { Field } from 'formik';
import SelectField from 'src/components/fields/SelectField';
import { fieldSpacingContainerStyle } from 'src/utils/field';
import MenuItem from '@mui/material/MenuItem';
import React from 'react';
import useEnterpriseEdition from 'src/utils/hooks/useEnterpriseEdition';
import ItemIcon from 'src/components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import AutocompleteField from '../../../../components/AutocompleteField';

const templateList = [{
  id: 'templateId0',
  name: 'templateName0',
  label: 'templateName0',
}, {
  id: 'templateId1',
  name: 'templateName1',
  label: 'templateName1',
},
{
  id: 'templateId2',
  name: 'templateName2',
  label: 'templateName2',
},
];

type MailTemplateFieldProps = {
  style: React.CSSProperties;
  name: string;
  label: string;
};

const MailTemplateField = ({ style, name, label }: MailTemplateFieldProps) => {
  const { t_i18n } = useFormatter();
  // const isEnterpriseEdition = useEnterpriseEdition();
  const isEnterpriseEdition = true;

  return (
    <Field
      disabled={!isEnterpriseEdition}
      style={style}
      component={AutocompleteField}
      variant="standard"
      textfieldprops={{
        variant: 'standard',
        label: t_i18n(label) ?? '',
      }}
      name={name}
      label={label}
      fullWidth={true}
      containerstyle={fieldSpacingContainerStyle}
      options={templateList}
      renderOption={(renderProps, template) => (
        <li {...renderProps}>
          <div style={{ display: 'inline-block', flexGrow: 1, marginLeft: 10 }}>{template.name}</div>
        </li>
      )}
    />
  );
};

export default MailTemplateField;
