import { Field, Form, Formik, FormikErrors } from 'formik';
import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { DeleteOutline } from '@mui/icons-material';
import Grid from '@mui/material/Grid';
import IconButton from '@common/button/IconButton';
import { ObjectSchema } from 'yup';
import TextField from '../../../../../components/TextField';
import ColorPickerField from '../../../../../components/ColorPickerField';
import { useFormatter } from '../../../../../components/i18n';
import type { Tick, UndefinedTick } from './scale';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  button: {
    display: 'flex',
    justifyContent: 'flex-end',
    alignItems: 'end',
    height: '100%',
  },
}));

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
  const classes = useStyles();
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
          <Form style={{ marginTop: noMargin ? 0 : 15 }}>
            <Grid container spacing={3} columns={13}>
              <Grid item xs={4} style={{ paddingTop: noMargin ? 0 : 24 }}>
                <Field
                  component={TextField}
                  type="number"
                  variant="standard"
                  name="value"
                  label={tickLabel}
                  fullWidth={true}
                  onSubmit={(name: keyof Tick, value: string) => handleUpdate(validateForm, name, value !== '' ? Number.parseInt(value, 10) : '')}
                />
              </Grid>
              <Grid item xs={4} style={{ paddingTop: noMargin ? 0 : 24 }}>
                <Field
                  component={ColorPickerField}
                  variant="standard"
                  name="color"
                  label={t_i18n('Color')}
                  fullWidth={true}
                  onSubmit={(name: keyof Tick, value: string) => handleUpdate(validateForm, name, value)}
                />
              </Grid>
              <Grid item xs={4} style={{ paddingTop: noMargin ? 0 : 24 }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name="label"
                  label={t_i18n('Label')}
                  fullWidth={true}
                  onSubmit={(name: keyof Tick, value: string) => handleUpdate(validateForm, name, value)}
                />
              </Grid>
              {deleteEnabled && (
                <Grid item xs={1} style={{ paddingTop: noMargin ? 0 : 24 }}>
                  <div className={classes.button}>
                    {handleDelete && (
                      <IconButton onClick={() => handleDelete()}>
                        <DeleteOutline fontSize="small" style={{ color: '#00b1ff' }} />
                      </IconButton>
                    )}
                  </div>
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
