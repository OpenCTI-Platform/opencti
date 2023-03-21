import { useFragment, useMutation } from 'react-relay';
import React, { useState } from 'react';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import {
  entitySettingFragment,
  entitySettingsPatch,
} from './EntitySetting';
import EntitySettingScale from './EntitySettingScale';
import { useFormatter } from '../../../../components/i18n';
import { handleError, MESSAGING$ } from '../../../../relay/environment';
import { EntitySetting_entitySetting$key } from './__generated__/EntitySetting_entitySetting.graphql';
import { SubType_subType$data } from './__generated__/SubType_subType.graphql';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
}));

export interface AttributeScaleConfiguration {
  name: string;
  mandatory?: boolean;
  scale?: Scale;
}

export interface Scale {
  local_config: ScaleConfig;
}

export interface ScaleConfig {
  better_side: string;
  min: Tick;
  max: Tick;
  ticks: Array<Tick | UndefinedTick>
}

export interface Tick {
  value: number;
  color: string;
  label: string;
}

export interface UndefinedTick {
  value: undefined
  label: string
  color: string
}

const EntitySettingAttributesConfigurationScale = ({
  entitySettingsData,
}: {
  entitySettingsData: SubType_subType$data['settings'];
}) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const entitySetting = useFragment<EntitySetting_entitySetting$key>(entitySettingFragment, entitySettingsData);
  if (!entitySetting) {
    return <></>;
  }

  const scaleAttributes = entitySetting.attributesDefinitions.filter((attr) => !!attr.scale);
  if (scaleAttributes.length === 0) {
    return <></>;
  }

  const hasAttributeConfiguration = entitySetting.availableSettings.includes('attributes_configuration');
  if (!hasAttributeConfiguration) {
    return <></>;
  }

  const attributesConfiguration: AttributeScaleConfiguration[] = entitySetting.attributes_configuration
    ? JSON.parse(entitySetting.attributes_configuration)
    : [];

  const [commit] = useMutation(entitySettingsPatch);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmitAttributeScale = (attributeName: string, scaleConfig: ScaleConfig) => {
    setSubmitting(true);
    const scale: Scale = { local_config: scaleConfig };
    const saveConfiguration = [...attributesConfiguration];
    const currentKeyValue = saveConfiguration.find((a) => a.name === attributeName);
    if (currentKeyValue) {
      currentKeyValue.scale = scale;
    } else {
      saveConfiguration.push({ name: attributeName, scale });
    }
    commit({
      variables: {
        ids: [entitySetting.id],
        input: {
          key: 'attributes_configuration',
          value: JSON.stringify(saveConfiguration),
        },
      },
      onCompleted: () => {
        setSubmitting(false);
        MESSAGING$.notifySuccess(t(`${attributeName} scale configuration has been successfully updated`));
      },
      onError: (error: Error) => {
        setSubmitting(false);
        handleError(error);
      },
    });
  };

  const getScaleConfig = (attributeScale: string) => {
    const scale = JSON.parse(attributeScale) as Scale;
    return scale.local_config;
  };

  return (
    <div>
      {scaleAttributes.map((attr) => (
        <Grid key={attr.name} container={true} spacing={3} style={{ paddingTop: 10 }}>
          <Grid item={true} xs={12}>
            <div style={{ marginTop: 30 }}>
              <Typography variant="h4" gutterBottom={true}>
                {t(`${attr.name} scale configuration`)}
              </Typography>
              <Paper classes={{ root: classes.paper }} variant="outlined">
                <EntitySettingScale
                  scaleConfig={getScaleConfig(attr.scale ?? '')}
                  submitting={submitting}
                  handleSubmit={(scale) => handleSubmitAttributeScale(attr.name, scale)}
                />
              </Paper>
            </div>
          </Grid>
        </Grid>
      ))}
    </div>
  );
};

export default EntitySettingAttributesConfigurationScale;
