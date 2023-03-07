import makeStyles from '@mui/styles/makeStyles';
import React, { useState, FunctionComponent } from 'react';
import * as Yup from 'yup';
import { Add } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import { Button } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import { MESSAGING$ } from '../../../../relay/environment';
import type { ScaleConfig, Tick, UndefinedTick } from './EntitySettingAttributesConfigurationScale';
import EntitySettingScaleTickLine from './EntitySettingScaleTickLine';

const useStyles = makeStyles(() => ({
  container: {
    padding: '10px 20px 20px 20px',
  },
}));

interface EntitySettingScaleProps {
  scaleConfig: ScaleConfig,
  submitting: boolean,
  handleSubmit: (scale: ScaleConfig) => void
}

const isTickDefinitionValid = (tickDefinition: ScaleConfig) => {
  let isValid = true;
  if (tickDefinition.min.value > tickDefinition.max.value) {
    MESSAGING$.notifyError('The min value cannot be greater than max value');
    return false;
  }
  tickDefinition.ticks.forEach((tick) => {
    if (!!tick.value && (tick.value < tickDefinition.min.value || tick.value > tickDefinition.max.value)) {
      MESSAGING$.notifyError('Each tick value must be between min and max value');
      isValid = false;
    }
  });
  return isValid;
};

const EntitySettingScale: FunctionComponent<EntitySettingScaleProps> = ({
  scaleConfig,
  submitting,
  handleSubmit,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const [tickDefinition, setTickDefinition] = useState<ScaleConfig>(scaleConfig);

  const { min, max } = tickDefinition;

  const tickValidation = () => {
    return Yup.object()
      .shape({
        label: Yup.string().required(t('This field is required')),
        color: Yup.string()
          .required(t('This field is required'))
          .matches(/^#[a-zA-Z0-9]{6}$/, t('The color must be written in hexadecimal. Example: #ff9800')),
        value: Yup.number()
          .required(t('This field is required'))
          .test('SchemaValidation', t('The value must be between min and max value'), (value) => {
            return !(!!value && (value < tickDefinition.min.value || value > tickDefinition.max.value));
          }),
      });
  };

  const minMaxValidation = () => {
    return Yup.object()
      .shape({
        label: Yup.string().required(t('This field is required')),
        color: Yup.string()
          .required(t('This field is required'))
          .matches(/^#[a-zA-Z0-9]{6}$/, t('The color must be written in hexadecimal. Example: #ff9800')),
        value: Yup.number()
          .required(t('This field is required'))
          .min(0, t('The value must be greater than or equal to 0'))
          .max(100, t('The value must be less than or equal to 100'))
          .test('MinMaxValidation', t('The min value cannot be greater than max value'), () => {
            return tickDefinition.min.value <= tickDefinition.max.value;
          }),
      });
  };

  const addTickRow = () => {
    const data: UndefinedTick = {
      value: undefined,
      color: '',
      label: '',
    };
    const newState = { ...tickDefinition };
    newState.ticks.push(data);
    setTickDefinition(newState);
  };
  const handleDeleteTickRow = (tickIndex: number | string) => {
    const newState = { ...tickDefinition };
    if (typeof tickIndex === 'number') { newState.ticks.splice(tickIndex, 1); }
    setTickDefinition(newState);
  };

  const sortTick = (a: Tick | UndefinedTick, b: Tick | UndefinedTick) => {
    if (!a?.value && a?.value !== 0) return -1;
    if (!b?.value && b?.value !== 0) return -1;
    return a.value - b.value;
  };

  const getTickRange = (ticks: Tick[], tickIndex: number, maxTick: Tick) => {
    if (tickIndex < 0 || ticks.length <= tickIndex) {
      return 0;
    }
    const tick = ticks.at(tickIndex);
    const nextTick = tickIndex < ticks.length - 1 ? ticks.at(tickIndex + 1) : maxTick;
    return (!!nextTick && !!tick) ? nextTick.value - tick.value : 0;
  };

  const getSortedTickWithMin = () => {
    const sortedTick = [min, ...tickDefinition.ticks] as Array<Tick>;
    return sortedTick.sort(sortTick);
  };

  const handleUpdateValueOfTick = (
    tickIndex: number | 'min' | 'max',
    property: keyof Tick,
    newValue: number | string,
  ) => {
    const newState = { ...tickDefinition };
    if (tickIndex === 'min') {
      newState.min[property] = newValue as never;
    } else if (tickIndex === 'max') {
      newState.max[property] = newValue as never;
    } else {
      const tick = newState.ticks[tickIndex as number];
      tick[property] = newValue as never;
    }
    setTickDefinition(newState);
  };

  const handleSubmitTickDefinition = () => {
    if (isTickDefinitionValid(tickDefinition)) {
      tickDefinition.ticks.sort(sortTick);
      handleSubmit(tickDefinition);
    }
  };

  return (
      <div style={{ height: '100%' }}>
        <div className={classes.container}>
          <EntitySettingScaleTickLine
            tick={tickDefinition.min}
            tickLabel={t('Min')}
            validation={minMaxValidation}
            handleUpdate={(name: keyof Tick, value: string | number) => handleUpdateValueOfTick('min', name, value)}
          />
          <EntitySettingScaleTickLine
            tick={tickDefinition.max}
            tickLabel={t('Max')}
            validation={minMaxValidation}
            handleUpdate={(name: keyof Tick, value: string | number) => handleUpdateValueOfTick('max', name, value)}
          />
          <Typography variant="h3" gutterBottom={true} style={{ float: 'left', margin: '10px 0' }}>
            {t('Ticks')}
          </Typography>
          <div style={{ padding: '20px 0' }}>
            {tickDefinition.ticks.map((tick, index) => (
              <EntitySettingScaleTickLine
                key={index}
                tick={tick}
                tickLabel={t('Value')}
                deleteEnabled={true}
                validation={tickValidation}
                handleUpdate={(name: keyof Tick, value: string | number) => handleUpdateValueOfTick(index, name, value)}
                handleDelete={() => handleDeleteTickRow(index)}
              />
            ))}
          </div>
          <Typography variant="h3" gutterBottom={true} style={{ float: 'right' }}>
            <IconButton
              onClick={addTickRow}
              color="secondary"
              aria-label="Label"
              size="large"
            >
              <Add fontSize="small" />
            </IconButton>
            {t('Add Tick')}
          </Typography>
          <div style={{ display: 'flex', width: '100%', padding: '20px 0' }}>
            {getSortedTickWithMin().map((tick, index) => (
              <div
                key={index}
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  flexGrow: `${getTickRange(getSortedTickWithMin(), index, max) / (max.value - min.value)}`,
                }}>
                <div className="rail">
                  <span className="railSpan" style={{
                    backgroundColor: `${tick.color ? tick.color : '#00b1ff'}`,
                    height: '5px',
                    width: '100%',
                    display: 'block',
                  }}></span>
                </div>
                <div style={{ display: 'flex', padding: '10px 0' }}>
                  <span style={{ color: `${index === 0 ? '#607d8b' : tick.color}` }}>{tick.value}</span>
                  <div style={{ flex: 1, textAlign: 'center' }}>{tick.label}</div>
                  { index === tickDefinition.ticks.length ? <span style={{ color: `${tick.color}` }}>{max.value}</span> : <></>}
                </div>
              </div>
            ))}
          </div>
          <div style={{ display: 'flex', justifyContent: 'right' }}>
            <Button
              type="submit"
              variant="contained"
              color="secondary"
              disabled={submitting}
              onClick={handleSubmitTickDefinition}>
              {t('Save')}
            </Button>
          </div>
        </div>
      </div>
  );
};

export default EntitySettingScale;
