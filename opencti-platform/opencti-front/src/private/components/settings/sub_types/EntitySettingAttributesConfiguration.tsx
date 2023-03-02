import { useMutation } from 'react-relay';
import React from 'react';
import Switch from '@mui/material/Switch';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import FormGroup from '@mui/material/FormGroup';
import FormControlLabel from '@mui/material/FormControlLabel';
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import { EntitySettingQuery } from './__generated__/EntitySettingQuery.graphql';
import { EntitySetting_entitySetting$key } from './__generated__/EntitySetting_entitySetting.graphql';
import { entitySettingFragment, entitySettingQuery, entitySettingsPatch } from './EntitySetting';
import { useFormatter } from '../../../../components/i18n';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(2, 1fr)',
  },
}));

export interface AttributeConfiguration {
  name: string
  mandatory: boolean
}

const EntitySettingAttributesConfiguration = ({ queryRef }: { queryRef: PreloadedQuery<EntitySettingQuery> }) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const entitySetting = usePreloadedFragment<EntitySettingQuery, EntitySetting_entitySetting$key>({
    linesQuery: entitySettingQuery,
    linesFragment: entitySettingFragment,
    queryRef,
    nodePath: 'entitySettingByType',
  });
  const attributesConfiguration: AttributeConfiguration[] = entitySetting.attributes_configuration
    ? JSON.parse(entitySetting.attributes_configuration) : [];

  const [commit] = useMutation(entitySettingsPatch);

  const handleSubmitField = (field: string, checked: boolean) => {
    const entitySettingsAttributesConfiguration = [...attributesConfiguration, { name: field, mandatory: checked }];
    commit({
      variables: {
        ids: [entitySetting.id],
        input: { key: 'attributes_configuration', value: JSON.stringify(entitySettingsAttributesConfiguration) },
      },
    });
  };

  const mandatoryAttributesBuiltIn: { name: string, mandatory: boolean, label: string }[] = [];
  const mandatoryAttributes: { name: string, mandatory: boolean, label: string }[] = [];

  entitySetting.mandatoryDefinitions.forEach((attr) => {
    const el = { name: attr.name, mandatory: attr.mandatory, label: attr.label ?? attr.name };
    if (attr.builtIn) {
      mandatoryAttributesBuiltIn.push(el);
    } else {
      mandatoryAttributes.push(el);
    }
  });
  const hasAttributeConfiguration = entitySetting.availableSettings.includes('attributes_configuration');
  if (hasAttributeConfiguration && (mandatoryAttributesBuiltIn.length > 0 || mandatoryAttributes.length > 0)) {
    return (
      <Grid item={true} xs={6}>
        <div style={{ height: '100%' }}>
          <Typography variant="h4" gutterBottom={true}>
            {t('Mandatory attributes')}
          </Typography>
          <Paper classes={{ root: classes.paper }} variant="outlined">
            {mandatoryAttributesBuiltIn.length > 0
                && <div style={{ marginBottom: 20 }}>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Built-in attributes')}
                </Typography><FormGroup classes={{ root: classes.grid }}>
                {mandatoryAttributesBuiltIn.map((attr) => (
                  <FormControlLabel
                    key={attr.name}
                    control={<Switch checked={attr.mandatory} disabled={true} />}
                    label={t(attr.label.charAt(0).toUpperCase() + attr.label.slice(1))} />
                ))}
              </FormGroup>
                </div>
            }
            {mandatoryAttributes.length > 0
              && <>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Customizable attributes')}
                </Typography>
                <FormGroup classes={{ root: classes.grid }}>
                  {mandatoryAttributes.map((attr) => (
                    <FormControlLabel
                      key={attr.name}
                      control={
                        <Switch checked={attr.mandatory}
                                onChange={(_, checked) => handleSubmitField(attr.name, checked)}
                        />
                      }
                      label={t(attr.label.charAt(0).toUpperCase() + attr.label.slice(1))}
                    />
                  ))}
                </FormGroup>
              </>
            }
          </Paper>
        </div>
      </Grid>
    );
  }
  return <></>;
};

export default EntitySettingAttributesConfiguration;
