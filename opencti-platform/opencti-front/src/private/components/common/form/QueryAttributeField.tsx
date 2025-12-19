import React, { FunctionComponent, ReactElement } from 'react';
import { Field, FieldArray } from 'formik';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { AddOutlined, DeleteOutlined } from '@mui/icons-material';
import Paper from '@mui/material/Paper';
import MenuItem from '@mui/material/MenuItem';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/fields/SelectField';

interface QueryAttributeFieldAddProps {
  id: string;
  name: string;
  values: {
    type: string;
    from: string;
    to: string;
    data_operation: string;
    state_operation: string;
    default: string;
    exposed: string;
  }[];
  containerStyle: { marginTop: number; width: string };
  setFieldValue?: (name: string, value: unknown) => void;
}

export const QueryAttributeFieldAdd: FunctionComponent<QueryAttributeFieldAddProps> = ({
  name,
  values,
  containerStyle,
}): ReactElement => {
  const { t_i18n } = useFormatter();
  return (
    <div style={containerStyle}>
      <FieldArray
        name={name}
        render={(arrayHelpers) => (
          <>
            <div id="total_attributes">
              {values?.map((_, index) => (

                <Paper
                  className="paper-for-grid"
                  variant="outlined"
                  key={index}
                  style={{ marginTop: 20, padding: 20, width: '100%', position: 'relative' }}
                >
                  <div
                    style={{
                      paddingRight: 50,
                      display: 'grid',
                      gap: 20,
                      gridTemplateColumns: 'repeat(2, 1fr)',
                    }}
                  >
                    <Field
                      component={SelectField}
                      variant="standard"
                      name={`${name}.${index}.type`}
                      label={t_i18n('Resolve from')}
                      fullWidth={true}
                      containerstyle={{ width: '100%' }}
                    >
                      <MenuItem value="data">{t_i18n('Data')}</MenuItem>
                      <MenuItem value="header">{t_i18n('Header')}</MenuItem>
                    </Field>

                    <Field
                      component={SelectField}
                      variant="standard"
                      name={`${name}.${index}.exposed`}
                      label={t_i18n('Exposed attribute to')}
                      fullWidth={true}
                      containerstyle={{ width: '100%' }}
                    >
                      <MenuItem value="body">{t_i18n('Body')}</MenuItem>
                      <MenuItem value="query_param">{t_i18n('Query parameter')}</MenuItem>
                      <MenuItem value="header">{t_i18n('Header')}</MenuItem>
                    </Field>

                    <Field
                      component={SelectField}
                      variant="standard"
                      name={`${name}.${index}.data_operation`}
                      label={t_i18n('Resolve operation')}
                      fullWidth={true}
                      containerstyle={{ width: '100%' }}
                    >
                      <MenuItem value="data">{t_i18n('Data')}</MenuItem>
                      <MenuItem value="count">{t_i18n('Count')}</MenuItem>
                    </Field>

                    <Field
                      component={SelectField}
                      variant="standard"
                      name={`${name}.${index}.state_operation`}
                      label={t_i18n('State operation')}
                      fullWidth={true}
                      containerstyle={{ width: '100%' }}
                    >
                      <MenuItem value="replace">{t_i18n('Replace')}</MenuItem>
                      <MenuItem value="sum">{t_i18n('Sum')}</MenuItem>
                    </Field>

                    <Field
                      component={TextField}
                      variant="standard"
                      name={`${name}.${index}.from`}
                      label={t_i18n('Get from path')}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      name={`${name}.${index}.to`}
                      label={t_i18n('To attribute name')}
                    />

                    <Field
                      component={TextField}
                      variant="standard"
                      name={`${name}.${index}.default`}
                      label={t_i18n('Default value')}
                    />

                  </div>
                  <IconButton
                    id="deleteHeader"
                    aria-label="Delete"
                    onClick={() => {
                      arrayHelpers.remove(index);
                    }}
                    style={{ position: 'absolute', right: 0, top: 5 }}
                  >
                    <DeleteOutlined />
                  </IconButton>
                </Paper>
              ))}
              <Button
                size="small"
                startIcon={<AddOutlined />}
                aria-label="Add"
                id="addHeader"
                onClick={() => {
                  arrayHelpers.push({
                    type: 'data',
                    from: '',
                    to: '',
                    data_operation: 'data',
                    state_operation: 'replace',
                    default: '',
                    exposed: 'body',
                  });
                }}
                style={{ marginTop: (values?.length ?? 0) > 0 ? 20 : 0 }}
              >
                {t_i18n('Add query attribute')}
              </Button>
            </div>
          </>
        )}
      />
    </div>
  );
};
