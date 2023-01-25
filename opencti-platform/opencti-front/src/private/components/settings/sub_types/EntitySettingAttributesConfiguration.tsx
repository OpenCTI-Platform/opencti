import { useMutation } from 'react-relay';
import React from 'react';
import Switch from '@mui/material/Switch';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { ListItem, ListItemText } from '@mui/material';
import List from '@mui/material/List';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import { EntitySettingQuery } from './__generated__/EntitySettingQuery.graphql';
import { EntitySetting_entitySetting$key } from './__generated__/EntitySetting_entitySetting.graphql';
import { SubType_subType$data } from './__generated__/SubType_subType.graphql';
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
}));

export interface AttributeConfiguration {
  name: string
  mandatory: boolean
}

const EntitySettingAttributesConfiguration = ({
  queryRef,
  subType,
}: {
  queryRef: PreloadedQuery<EntitySettingQuery>;
  subType: SubType_subType$data,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const entitySetting = usePreloadedFragment<
  EntitySettingQuery,
  EntitySetting_entitySetting$key
  >({
    linesQuery: entitySettingQuery,
    linesFragment: entitySettingFragment,
    queryRef,
    nodePath: 'entitySettingByType',
  });

  let attributesConfiguration: AttributeConfiguration[] = [];
  if (entitySetting.attributes_configuration) {
    attributesConfiguration = JSON.parse(entitySetting.attributes_configuration);
  }

  const [commit] = useMutation(entitySettingsPatch);

  const handleSubmitField = (field: string, checked: boolean) => {
    let entitySettingsAttributesConfiguration;

    if (checked) {
      entitySettingsAttributesConfiguration = [...attributesConfiguration ?? [], { name: field, mandatory: true }];
    } else {
      entitySettingsAttributesConfiguration = attributesConfiguration?.filter((attr) => attr?.name !== field);
    }

    commit({
      variables: {
        ids: [entitySetting.id],
        input: { key: 'attributes_configuration', value: JSON.stringify(entitySettingsAttributesConfiguration) },
      },
    });
  };

  const isMandatoryAttributeConfiguration = (name: string): boolean => {
    return attributesConfiguration?.filter((attr) => attr.mandatory)
      .map((attr) => attr?.name).includes(name);
  };

  const mandatoryAttributes = subType.mandatoryAttributes.map((attr) => ({
    builtIn: attr.builtIn,
    mandatory: attr.mandatory || isMandatoryAttributeConfiguration(attr.name),
    name: attr.name,
  }));

  return (
    <Grid item={true} xs={6}>
      <div>
        <Typography variant="h4" gutterBottom={true}>
          {t('Mandatory attributes')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <span>Mandatory attributes</span>
          <List>
            {mandatoryAttributes.map((attr) => (
              <ListItem>
                <ListItemText
                  primary={
                    <div>
                      <span>{attr.name}</span>
                      <Switch checked={attr.mandatory}
                              disabled={attr.builtIn}
                              onChange={(_, checked) => handleSubmitField(attr.name, checked)}
                      />
                    </div>
                  }
                />
              </ListItem>
            ))}
          </List>
        </Paper>
      </div>
    </Grid>
  );
};

export default EntitySettingAttributesConfiguration;
