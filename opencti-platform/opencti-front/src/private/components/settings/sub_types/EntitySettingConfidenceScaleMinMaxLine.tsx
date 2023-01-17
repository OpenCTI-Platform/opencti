import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import makeStyles from '@mui/styles/makeStyles';
import TextField from '../../../../components/TextField';
import ColorPickerField from '../../../../components/ColorPickerField';
import type { Tick, UndefinedTick } from './EntitySettingConfidenceScale';
import { useFormatter } from '../../../../components/i18n';

const useStyles = makeStyles(() => ({
  input: {
    display: 'flex',
    justifyContent: 'space-between',
    marginTop: '10px',
  },
}));

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
            handleUpdate(name, value !== '' ? Number.parseInt((value), 10) : '');
          }
        };
        return (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <div className={classes.input}>
              <Field
                component={TextField}
                variant="standard"
                name="value"
                label={tickName}
                fullWidth={false}
                multiline
                onSubmit={handleTickValueUpdate}
              />
              <Field
                component={ColorPickerField}
                variant="standard"
                name="color"
                label={t('Color')}
                fullWidth={false}
                multiline
                onSubmit={handleUpdate}
              />
              <Field
                component={TextField}
                variant="standard"
                name="label"
                label={t('Label')}
                fullWidth={false}
                multiline
                onSubmit={handleUpdate}
              />
              <div style={{ width: '64px' }}></div>
            </div>
          </Form>
        );
      }}
    </Formik>
  );
};

export default EntitySettingsConfidenceScaleMinMaxLine;
