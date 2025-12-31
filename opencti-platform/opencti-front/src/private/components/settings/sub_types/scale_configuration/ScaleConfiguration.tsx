import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent, useState } from 'react';
import * as Yup from 'yup';
import { FormikErrors, FormikValues } from 'formik';
import { clone } from 'ramda';
import { Add } from '@mui/icons-material';
import { FormControl, IconButton, InputLabel, MenuItem, Paper, Select, Typography } from '@mui/material';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import { allScales, customScaleName, findSelectedScaleName } from '../../../../../utils/hooks/useScale';
import type { ScaleConfig, Tick, UndefinedTick } from './scale';
import ScaleConfigurationLine from './ScaleConfigurationLine';
import ScaleBar from './ScaleBar';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    height: '100%',
    position: 'relative',
    paddingBottom: 50,
  },
  createButton: {
    float: 'left',
    marginTop: -15,
    marginBottom: 0,
  },
  paper: {
    marginTop: theme.spacing(1),
    padding: 15,
    borderRadius: 4,
  },
}));

const minMaxValidation = (
  t: (value: string) => string,
  min: number,
  max: number,
) => {
  return Yup.object().shape({
    label: Yup.string().required(t('This field is required')),
    color: Yup.string()
      .required(t('This field is required'))
      .matches(
        /^#[a-zA-Z0-9]{6}$/,
        t('The color must be written in hexadecimal. Example: #ff9800'),
      ),
    value: Yup.number()
      .required(t('This field is required'))
      .min(0, t('The value must be greater than or equal to 0'))
      .max(100, t('The value must be less than or equal to 100'))
      .test(
        'MinMaxValidation',
        t('The minimum value cannot be greater than maximum value'),
        () => min <= max,
      ),
  });
};

const tickValidation = (
  t: (value: string) => string,
  min: number,
  max: number,
) => {
  return Yup.object().shape({
    label: Yup.string().required(t('This field is required')),
    color: Yup.string()
      .required(t('This field is required'))
      .matches(
        /^#[a-zA-Z0-9]{6}$/,
        t('The color must be written in hexadecimal. Example: #ff9800'),
      ),
    value: Yup.number()
      .required(t('This field is required'))
      .test(
        'SchemaValidation',
        t('The value must be between minimum and maximum value'),
        (value) => !(!!value && (value < min || value > max)),
      ),
  });
};

const isTickDefinitionValid = (
  tickDefinition: ScaleConfig,
  setErrors: (errors: FormikErrors<FormikValues>) => void,
  fieldName: string,
) => {
  let isValid = true;
  if (tickDefinition.min.value > tickDefinition.max.value) {
    setErrors({
      [fieldName]: 'The minimum value cannot be greater than max value',
    });
    return false;
  }
  tickDefinition.ticks.forEach((tick) => {
    if (
      !tick.value
      || Number(tick.value) < tickDefinition.min.value
      || Number(tick.value) > tickDefinition.max.value
    ) {
      setErrors({
        [fieldName]:
          'Each tick value must be between minimum and maximum value',
      });
      isValid = false;
    }
  });
  return isValid;
};

interface EntitySettingScaleProps {
  initialValues: ScaleConfig;
  fieldName: string;
  setFieldValue: (
    field: string,
    value: ScaleConfig,
    shouldValidate?: boolean,
  ) => void;
  setErrors: (errors: FormikErrors<FormikValues>) => void;
  customScale?: ScaleConfig | null;
  style?: Record<string, string | number>;
}

const ScaleConfiguration: FunctionComponent<EntitySettingScaleProps> = ({
  initialValues,
  fieldName,
  setFieldValue,
  setErrors,
  customScale,
  style,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();

  const [tickDefinition, setTickDefinition] = useState<ScaleConfig>(
    clone(initialValues),
  );

  const sortTick = (a: Tick | UndefinedTick, b: Tick | UndefinedTick) => {
    if (typeof a.value === 'string') return -1;
    if (typeof b.value === 'string') return -1;
    return a.value - b.value;
  };

  const update = (values: ScaleConfig) => {
    values.ticks.sort(sortTick);
    setTickDefinition(values);
    if (isTickDefinitionValid(tickDefinition, setErrors, fieldName)) {
      setFieldValue(fieldName, values);
    }
  };

  const addTickRow = () => {
    const data: UndefinedTick = {
      value: '',
      color: '',
      label: '',
    };
    const newState = { ...tickDefinition };
    newState.ticks.push(data);
    update(newState);
  };
  const handleDeleteTickRow = (tickIndex: number) => {
    const newState = { ...tickDefinition };
    newState.ticks.splice(tickIndex, 1);
    update(newState);
  };

  const handleUpdateValueOfTick = (
    validateForm: (
      values?: Tick | UndefinedTick,
    ) => Promise<FormikErrors<Tick | UndefinedTick>>,
    tickIndex: number | 'min' | 'max',
    property: keyof Tick,
    newValue: number | string,
  ) => {
    validateForm().then((errors) => {
      setErrors(errors);
      const newState = { ...tickDefinition };
      if (tickIndex === 'min') {
        newState.min[property] = newValue as never;
      } else if (tickIndex === 'max') {
        newState.max[property] = newValue as never;
      } else {
        const tick = newState.ticks[tickIndex as number];
        tick[property] = newValue as never;
      }
      update(newState);
    });
  };

  const currentScaleName = findSelectedScaleName(tickDefinition);
  const selectorScales = customScale
    ? [{ name: customScaleName, scale: customScale }, ...allScales]
    : [...allScales];
  const selectScale = (name: string) => {
    const scaleSelected = selectorScales.find((scale) => scale.name === name);
    if (scaleSelected) {
      const newState = clone(scaleSelected.scale);
      update(newState);
    }
  };

  return (
    <div style={style}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Scale configuration')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <div className={classes.container}>
          <FormControl sx={{ m: 1, minWidth: 140, margin: 0 }}>
            <InputLabel id="scale-selector">
              {t_i18n('Selected scale template')}
            </InputLabel>
            <Select
              labelId="scale-selector"
              value={currentScaleName}
              onChange={(event) => selectScale(event.target.value)}
            >
              {selectorScales.map((scale, i: number) => {
                return (
                  <MenuItem key={i} value={scale.name}>
                    {scale.name}
                  </MenuItem>
                );
              })}
            </Select>
          </FormControl>
          <ScaleBar scale={tickDefinition} />
          <Typography variant="h4">{t_i18n('Customize scale')}</Typography>
          <Typography variant="h3" gutterBottom={true}>
            {t_i18n('Limits')}
          </Typography>
          <ScaleConfigurationLine
            tick={tickDefinition.min}
            tickLabel={t_i18n('Minimum')}
            validation={() => minMaxValidation(
              t_i18n,
              tickDefinition.min.value,
              tickDefinition.max.value,
            )
            }
            handleUpdate={(
              validateForm,
              name: keyof Tick,
              value: string | number,
            ) => handleUpdateValueOfTick(validateForm, 'min', name, value)}
          />
          <ScaleConfigurationLine
            tick={tickDefinition.max}
            tickLabel={t_i18n('Maximum')}
            validation={() => minMaxValidation(
              t_i18n,
              tickDefinition.min.value,
              tickDefinition.max.value,
            )
            }
            handleUpdate={(
              validateForm,
              name: keyof Tick,
              value: string | number,
            ) => handleUpdateValueOfTick(validateForm, 'max', name, value)}
          />
          <div style={{ marginTop: 30, float: 'left' }}>
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ float: 'left', marginBottom: 0 }}
            >
              {t_i18n('Ticks')}
            </Typography>
            <IconButton
              color="secondary"
              aria-label="Add"
              onClick={addTickRow}
              classes={{ root: classes.createButton }}
            >
              <Add fontSize="small" />
            </IconButton>
          </div>
          {tickDefinition.ticks.map((tick, index) => (
            <ScaleConfigurationLine
              key={index}
              tick={tick}
              tickLabel={t_i18n('Value')}
              deleteEnabled={true}
              validation={() => tickValidation(
                t_i18n,
                tickDefinition.min.value,
                tickDefinition.max.value,
              )
              }
              handleUpdate={(
                validateForm,
                name: keyof Tick,
                value: string | number,
              ) => handleUpdateValueOfTick(validateForm, index, name, value)}
              handleDelete={() => handleDeleteTickRow(index)}
              noMargin={index === 0}
            />
          ))}
        </div>
      </Paper>
    </div>
  );
};

export default ScaleConfiguration;
