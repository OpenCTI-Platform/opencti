import { Field, Form, Formik } from 'formik';
import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { DeleteOutline } from '@mui/icons-material';
import Grid from '@mui/material/Grid';
import BaseSchema from 'yup/lib/schema';
import IconButton from '@mui/material/IconButton';
import TextField from '../../../../components/TextField';
import ColorPickerField from '../../../../components/ColorPickerField';
import type {
  Tick,
  UndefinedTick,
} from './EntitySettingAttributesConfigurationScale';
import { useFormatter } from '../../../../components/i18n';

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
  validation: (t: (v: string) => string) => BaseSchema;
  handleUpdate: (name: keyof Tick, value: number | string) => void;
  handleDelete?: () => void;
  noMargin?: boolean;
}

const EntitySettingScaleTickLine: FunctionComponent<
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
            handleUpdate(name, value !== '' ? Number.parseInt(value, 10) : '');
          }
        };
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
                  onSubmit={handleTickValueUpdate}
                />
              </Grid>
              <Grid item xs={4} style={{ paddingTop: noMargin ? 0 : 24 }}>
                <Field
                  component={ColorPickerField}
                  variant="standard"
                  name="color"
                  label={t('Color')}
                  fullWidth={true}
                  onSubmit={(name: keyof Tick, value: string) => handleUpdate(name, value)
                  }
                />
              </Grid>
              <Grid item xs={4} style={{ paddingTop: noMargin ? 0 : 24 }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name="label"
                  label={t('Label')}
                  fullWidth={true}
                  onSubmit={(name: keyof Tick, value: string) => handleUpdate(name, value)
                  }
                />
              </Grid>
              {deleteEnabled && (
                <Grid item xs={1} style={{ paddingTop: noMargin ? 0 : 24 }}>
                  <div className={classes.button}>
                    {handleDelete && (
                      <IconButton onClick={() => handleDelete()}>
                        <DeleteOutline
                          fontSize="small"
                          style={{ color: '#00b1ff' }}
                        />
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

export default EntitySettingScaleTickLine;
