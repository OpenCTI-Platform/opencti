import React, { FunctionComponent, ReactElement } from 'react';
import { Field, FieldArray } from 'formik';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { AddOutlined, DeleteOutlined } from '@mui/icons-material';
import { Paper } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import SelectFieldFds, { SelectItem } from '../../../../components/fields/SelectFieldFds';

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
                  padding={24}
                  className="paper-for-grid"
                  key={index}
                  style={{ marginTop: 20, width: '100%', position: 'relative' }}
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
                      component={SelectFieldFds}
                      variant="standard"
                      name={`${name}.${index}.type`}
                      label={t_i18n('Resolve from')}
                      fullWidth={true}
                      containerstyle={{ width: '100%' }}
                    >
                      <SelectItem value="data">{t_i18n('Data')}</SelectItem>
                      <SelectItem value="header">{t_i18n('Header')}</SelectItem>
                    </Field>

                    <Field
                      component={SelectFieldFds}
                      variant="standard"
                      name={`${name}.${index}.exposed`}
                      label={t_i18n('Exposed attribute to')}
                      fullWidth={true}
                      containerstyle={{ width: '100%' }}
                    >
                      <SelectItem value="body">{t_i18n('Body')}</SelectItem>
                      <SelectItem value="query_param">{t_i18n('Query parameter')}</SelectItem>
                      <SelectItem value="header">{t_i18n('Header')}</SelectItem>
                    </Field>

                    <Field
                      component={SelectFieldFds}
                      variant="standard"
                      name={`${name}.${index}.data_operation`}
                      label={t_i18n('Resolve operation')}
                      fullWidth={true}
                      containerstyle={{ width: '100%' }}
                    >
                      <SelectItem value="data">{t_i18n('Data')}</SelectItem>
                      <SelectItem value="count">{t_i18n('Count')}</SelectItem>
                    </Field>

                    <Field
                      component={SelectFieldFds}
                      variant="standard"
                      name={`${name}.${index}.state_operation`}
                      label={t_i18n('State operation')}
                      fullWidth={true}
                      containerstyle={{ width: '100%' }}
                    >
                      <SelectItem value="replace">{t_i18n('Replace')}</SelectItem>
                      <SelectItem value="sum">{t_i18n('Sum')}</SelectItem>
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
