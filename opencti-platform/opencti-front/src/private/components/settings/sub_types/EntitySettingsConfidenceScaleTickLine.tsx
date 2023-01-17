import { Field, Form, Formik } from 'formik';
import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { Button } from '@mui/material';
import { DeleteOutline } from '@mui/icons-material';
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
          <Form style={{ margin: '20px 0 20px 0' }}>
            <div className={classes.input}>
              <Field
                component={TextField}
                variant="standard"
                name="value"
                label={t('Value')}
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
                onSubmit={(name: keyof Tick, value: string) => handleUpdate(tickIndex, name, value)}
              />
              <Field
                component={TextField}
                variant="standard"
                name="label"
                label={t('Label')}
                fullWidth={false}
                multiline
                onSubmit={(name: keyof Tick, value: string) => handleUpdate(tickIndex, name, value)}
              />
              <div style={{ alignSelf: 'center' }}>
                { handleDelete && <Button onClick={() => handleDelete(tickIndex)}>
                  <DeleteOutline fontSize="small" />
                </Button> }
              </div>
            </div>
          </Form>
        );
      }}
    </Formik>
  );
};

export default EntitySettingsConfidenceScaleTickLine;
