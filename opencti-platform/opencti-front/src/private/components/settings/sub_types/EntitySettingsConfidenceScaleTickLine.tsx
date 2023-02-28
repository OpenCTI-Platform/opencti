import { Field, Form, Formik } from 'formik';
import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { Button } from '@mui/material';
import { DeleteOutline } from '@mui/icons-material';
import Grid from '@mui/material/Grid';
import TextField from '../../../../components/TextField';
import ColorPickerField from '../../../../components/ColorPickerField';
import type { Tick, UndefinedTick } from './EntitySettingConfidenceScale';
import { useFormatter } from '../../../../components/i18n';

const useStyles = makeStyles(() => ({
  button: {
    display: 'flex',
    justifyContent: 'flex-end',
    alignItems: 'end',
    height: '100%',
  },
}));

interface EntitySettingsConfidenceScaleTickLineProps {
  tick: Tick | UndefinedTick,
  tickIndex: number,
  validation: (t: (v: string) => string) => void,
  handleUpdate: (tickIndex: number, name: keyof Tick, value: number | string) => void,
  handleDelete?: (tickIndex: number | string) => void,
}

const EntitySettingsConfidenceScaleTickLine: FunctionComponent<EntitySettingsConfidenceScaleTickLineProps> = ({
  tick,
  tickIndex,
  validation,
  handleUpdate,
  handleDelete,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();

  return (
    <Formik
      enableReinitialize={true}
      initialValues={tick}
      validationSchema={validation(t)}
      onSubmit={() => {}}
    >
      {() => {
        const handleTickValueUpdate = (name: keyof Tick, value: string) => {
          if (handleUpdate) {
            handleUpdate(tickIndex, name, value !== '' ? Number.parseInt((value), 10) : '');
          }
        };
        return (
          <Form style={{ margin: '30px 0' }}>
            <Grid container spacing={3} columns={13}>
              <Grid item xs={4}>
                <Field
                  component={TextField}
                  variant="standard"
                  name="value"
                  label={t('Value')}
                  fullWidth={true}
                  multiline
                  onSubmit={handleTickValueUpdate}
                />
              </Grid>
              <Grid item xs={4}>
                <Field
                  component={ColorPickerField}
                  variant="standard"
                  name="color"
                  label={t('Color')}
                  style={{ width: '100%' }}
                  multiline
                  onSubmit={(name: keyof Tick, value: string) => handleUpdate(tickIndex, name, value)}
                />
              </Grid>
              <Grid item xs={4}>
                <Field
                  component={TextField}
                  variant="standard"
                  name="label"
                  label={t('Label')}
                  fullWidth={true}
                  multiline
                  onSubmit={(name: keyof Tick, value: string) => handleUpdate(tickIndex, name, value)}
                />
              </Grid>
              <Grid item xs={1}>
                <div className={classes.button}>
                  { handleDelete && <Button onClick={() => handleDelete(tickIndex)}>
                    <DeleteOutline fontSize="small" />
                  </Button> }
                </div>
              </Grid>
            </Grid>
        </Form>
        );
      }}
    </Formik>
  );
};

export default EntitySettingsConfidenceScaleTickLine;
