import makeStyles from '@mui/styles/makeStyles';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { useMutation } from 'react-relay';
import React, { useState, FunctionComponent } from 'react';
import * as Yup from 'yup';
import { Add } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import { Button } from '@mui/material';
import { EntitySettingQuery } from './__generated__/EntitySettingQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import { EntitySetting_entitySetting$key } from './__generated__/EntitySetting_entitySetting.graphql';
import { entitySettingFragment, entitySettingQuery, entitySettingsPatch } from './EntitySetting';
import { EntitySettingsPatchMutation } from './__generated__/EntitySettingsPatchMutation.graphql';
import { Theme } from '../../../../components/Theme';
import EntitySettingsConfidenceScaleTickLine from './EntitySettingsConfidenceScaleTickLine';
import EntitySettingsConfidenceScaleMinMaxLine from './EntitySettingConfidenceScaleMinMaxLine';
import { handleError, MESSAGING$ } from '../../../../relay/environment';

const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  thumb: {
    width: '10px',
  },
  mark: {
    background: 'black',
  },
  track: {
    background: 'none',
    border: 'none',
  },
  valueLabel: {
    '&>*': {
      background: 'black',
    },
  },
  input: {
    display: 'flex',
    justifyContent: 'space-between',
    marginTop: '10px',
  },
}));

const isTickDefinitionValid = (tickDefinition: ConfidenceScaleConfiguration) => {
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

export interface Tick {
  value: number
  label: string
  color: string
}

export interface UndefinedTick {
  value: undefined
  label: string
  color: string
}

export interface TickDefinition {
  [key: string]: Tick
}

export interface ConfidenceScaleConfiguration {
  min: Tick
  max: Tick
  ticks: Array<Tick | UndefinedTick>
}

interface EntitySettingConfidenceScaleProps {
  entitySettingId: string
  localConfig: ConfidenceScaleConfiguration
}

const EntitySettingConfidenceScaleComponent: FunctionComponent<EntitySettingConfidenceScaleProps> = ({ localConfig: confidenceScale, entitySettingId }) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const [tickDefinition, setTickDefinition] = useState<ConfidenceScaleConfiguration>(confidenceScale);
  const [submitting, setSubmitting] = useState(false);
  const [commit] = useMutation<EntitySettingsPatchMutation>(entitySettingsPatch);

  const { min, max } = tickDefinition;

  const tickValidation = () => {
    return Yup.object()
      .shape({
        label: Yup.string().required(t('This field is required')),
        color: Yup.string().required(t('This field is required')),
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
        color: Yup.string().required(t('This field is required')),
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
    commit({
      variables: {
        ids: [entitySettingId],
        input: [{
          key: 'confidence_scale',
          value: [JSON.stringify({ localConfig: tickDefinition })],
        }],
      },
    });
  };

  const sortTick = (a: Tick | UndefinedTick, b: Tick | UndefinedTick) => {
    if (!a?.value) return 1;
    if (!b?.value) return -1;
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
    return [min, ...tickDefinition.ticks.sort(sortTick)] as Array<Tick>;
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

  const handleSubmit = () => {
    if (isTickDefinitionValid(tickDefinition)) {
      setSubmitting(true);
      commit({
        variables: {
          ids: [entitySettingId],
          input: [{
            key: 'confidence_scale',
            value: [JSON.stringify({
              localConfig: tickDefinition,
            })],
          }],
        },
        onCompleted: () => {
          setSubmitting(false);
          MESSAGING$.notifySuccess(t('Confidence scale configuration has been successfully updated'));
        },
        onError: (error: Error) => {
          setSubmitting(false);
          handleError(error);
        },
      });
    }
  };

  return (
      <div style={{ height: '100%' }}>
        <div className={classes.container}>
          <EntitySettingsConfidenceScaleMinMaxLine
            tick={tickDefinition.min}
            tickName={'Min'}
            validation={minMaxValidation}
            handleUpdate={(name: keyof Tick, value: string | number) => handleUpdateValueOfTick('min', name, value)}
          />
          <EntitySettingsConfidenceScaleMinMaxLine
            tick={tickDefinition.max}
            tickName={'Max'}
            validation={minMaxValidation}
            handleUpdate={(name: keyof Tick, value: string | number) => handleUpdateValueOfTick('max', name, value)}
          />
          <Typography variant="h3" gutterBottom={true} style={{ float: 'left', margin: '10px 0' }}>
            {t('Add Tick')}
            <IconButton
              onClick={addTickRow}
              color="secondary"
              aria-label="Label"
              size="large"
            >
              <Add fontSize="small" />
            </IconButton>
          </Typography>
          <div style={{ padding: '60px 0' }}>
            {tickDefinition.ticks.sort(sortTick).map((tick, index) => (
              <EntitySettingsConfidenceScaleTickLine
                tick={tick}
                tickIndex={index}
                validation={tickValidation}
                handleUpdate={handleUpdateValueOfTick}
                handleDelete={handleDeleteTickRow}
              />
            ))}
          </div>
          <div style={{ display: 'flex', width: '100%', padding: '20px 0' }}>
            {getSortedTickWithMin().map((tick, index) => (
              <div style={{ display: 'flex',
                flexDirection: 'column',
                flexGrow: `${getTickRange(
                  getSortedTickWithMin(),
                  index,
                  max,
                ) / max.value}` }}>
                <div className="rail">
                  <span className="railSpan" style={{
                    backgroundColor: `${tick.color}`,
                    height: '5px',
                    width: '100%',
                    display: 'block',
                  }}></span>
                </div>
                <div className="valueAndLabel" style={{ display: 'flex', padding: '10px 0' }}>
                  <span style={{ color: `${tick.color}` }}>{tick.value}</span>
                  <div style={{ flex: 1, textAlign: 'center' }}>{tick.label}</div>
                  { index === tickDefinition.ticks.length ? <span style={{ color: `${max.color}` }}>{max.value}</span> : <></>}
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
              onClick={handleSubmit}>
              {t('Save')}
            </Button>
          </div>
        </div>
      </div>
  );
};

const EntitySettingConfidenceScale = ({ queryRef }: { queryRef: PreloadedQuery<EntitySettingQuery> }) => {
  const entitySetting = usePreloadedFragment<
  EntitySettingQuery,
  EntitySetting_entitySetting$key
  >({
    linesQuery: entitySettingQuery,
    linesFragment: entitySettingFragment,
    queryRef,
    nodePath: 'entitySettingByType',
  });

  if (entitySetting.confidence_scale) {
    const { localConfig } = JSON.parse(entitySetting.confidence_scale);
    return (
        <EntitySettingConfidenceScaleComponent localConfig={localConfig} entitySettingId={entitySetting.id} />
    );
  }
  return (
      <></>
  );
};

export default EntitySettingConfidenceScale;
