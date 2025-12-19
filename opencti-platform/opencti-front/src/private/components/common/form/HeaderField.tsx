import React, { FunctionComponent, ReactElement } from 'react';
import { Field, FieldArray } from 'formik';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { AddOutlined, DeleteOutlined } from '@mui/icons-material';
import Paper from '@mui/material/Paper';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';

interface HeaderFieldAddProps {
  id: string;
  name: string;
  values: { name: string; value: string }[];
  containerStyle: { marginTop: number; width: string };
  setFieldValue?: (name: string, value: unknown) => void;
}

export const HeaderFieldAdd: FunctionComponent<HeaderFieldAddProps> = ({
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
            <div id="total_headers">
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
                      component={TextField}
                      variant="standard"
                      name={`${name}.${index}.name`}
                      label={t_i18n('Header name')}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      name={`${name}.${index}.value`}
                      label={t_i18n('Header value')}
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
                  arrayHelpers.push({ name: '', value: '' });
                }}
                style={{ marginTop: (values?.length ?? 0) > 0 ? 20 : 0 }}
              >
                {t_i18n('Add header')}
              </Button>
            </div>
          </>
        )}
      />
    </div>
  );
};
