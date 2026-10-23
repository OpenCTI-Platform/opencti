import { Field, Form, Formik, FormikErrors } from 'formik';
import React, { FunctionComponent } from 'react';
import { DeleteOutlined } from '@mui/icons-material';
import Box from '@mui/material/Box';
import Grid from '@mui/material/Grid';
import IconButton from '@common/button/IconButton';
import { ObjectSchema } from 'yup';
import TextField from '../../../../../components/TextField';
import ColorPickerField from '../../../../../components/ColorPickerField';
import { useFormatter } from '../../../../../components/i18n';
import type { Tick, UndefinedTick } from './scale';

interface EntitySettingScaleTickLineProps {
  tick: Tick | UndefinedTick;
  tickLabel: string;
  deleteEnabled?: boolean;
  validation: (t: (v: string) => string, min: number, max: number) => ObjectSchema<{ [p: string]: unknown }>;
  handleUpdate: (validateForm: (values?: Tick | UndefinedTick) => Promise<FormikErrors<Tick | UndefinedTick>>, name: keyof Tick, value: number | string) => void;
  handleDelete?: () => void;
  noMargin?: boolean;
}

const ScaleConfigurationLine: FunctionComponent<
  EntitySettingScaleTickLineProps
> = ({
  tick,
  tickLabel,
  deleteEnabled,
  validation,
  handleUpdate,
  handleDelete,
  noMargin,
}) => {
  const { t_i18n } = useFormatter();

  return (
    <Formik
      enableReinitialize={true}
      initialValues={tick}
      validationSchema={validation}
      onSubmit={() => {}}
    >
      {({ validateForm }) => {
        return (
          <Form style={{ marginTop: noMargin ? -24 : 15 }}>
            <Grid container spacing={3} columns={13}>
              <Grid size={4}>
                <Field
                  component={TextField}
                  type="number"
                  variant="outlined"
                  name="value"
                  label={tickLabel}
                  fullWidth={true}
                  onSubmit={(name: keyof Tick, value: string) => handleUpdate(validateForm, name, value !== '' ? Number.parseInt(value, 10) : '')}
                />
              </Grid>
              <Grid size={4}>
                <Field
                  component={ColorPickerField}
                  variant="outlined"
                  name="color"
                  label={t_i18n('Color')}
                  fullWidth={true}
                  onSubmit={(name: keyof Tick, value: string) => handleUpdate(validateForm, name, value)}
                />
              </Grid>
              <Grid size={4}>
                <Field
                  component={TextField}
                  variant="outlined"
                  name="label"
                  label={t_i18n('Label')}
                  fullWidth={true}
                  onSubmit={(name: keyof Tick, value: string) => handleUpdate(validateForm, name, value)}
                />
              </Grid>
              {deleteEnabled && (
                <Grid size={1}>
                  <Box
                    sx={{
                      display: 'flex',
                      justifyContent: 'flex-end',
                      alignItems: 'end',
                      height: '100%',
                    }}
                  >
                    {handleDelete && (
                      <IconButton aria-label={t_i18n('Delete')} onClick={() => handleDelete()}>
                        <DeleteOutlined fontSize="small" style={{ color: '#00b1ff' }} />
                      </IconButton>
                    )}
                  </Box>
                </Grid>
              )}
            </Grid>
          </Form>
        );
      }}
    </Formik>
  );
};

export default ScaleConfigurationLine;
