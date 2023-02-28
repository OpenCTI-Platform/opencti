import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import Grid from '@mui/material/Grid';
import TextField from '../../../../components/TextField';
import ColorPickerField from '../../../../components/ColorPickerField';
import type { Tick, UndefinedTick } from './EntitySettingConfidenceScale';
import { useFormatter } from '../../../../components/i18n';

interface EntitySettingsConfidenceScaleMinMaxLineProps {
  tick: Tick | UndefinedTick,
  tickName: string,
  validation: (t: (v: string) => string) => void,
  handleUpdate: (name: keyof Tick, value: number | string) => void,
}

const EntitySettingsConfidenceScaleMinMaxLine: FunctionComponent<EntitySettingsConfidenceScaleMinMaxLineProps> = ({
  tick,
  tickName,
  validation,
  handleUpdate,
}) => {
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
            handleUpdate(name, value !== '' ? Number.parseInt((value), 10) : '');
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
                  label={tickName}
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
                  onSubmit={handleUpdate}
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
                  onSubmit={handleUpdate}
                />
              </Grid>
            </Grid>
          </Form>
        );
      }}
    </Formik>
  );
};

export default EntitySettingsConfidenceScaleMinMaxLine;
