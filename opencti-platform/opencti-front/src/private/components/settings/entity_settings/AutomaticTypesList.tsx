import MenuItem from '@mui/material/MenuItem';
import Checkbox from '@mui/material/Checkbox';
import React, { useState } from 'react';
import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import { Field } from 'formik';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { useFragment, useMutation } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import {
  EntitySettingConnection_entitySettings$key,
} from '../sub_types/__generated__/EntitySettingConnection_entitySettings.graphql';
import {
  entitySettingFragment,
  entitySettingsFragment,
  entitySettingsPatch,
  entitySettingsQuery,
} from '../sub_types/EntitySetting';
import { EntitySetting_entitySetting$data } from '../sub_types/__generated__/EntitySetting_entitySetting.graphql';
import { EntitySettingsQuery } from '../sub_types/__generated__/EntitySettingsQuery.graphql';

const AutomaticTypesList = ({ queryRef }: { queryRef: PreloadedQuery<EntitySettingsQuery> }) => {
  const { t } = useFormatter();

  const filterEntityFilesRef = (node: EntitySetting_entitySetting$data) => node.platform_entity_files_ref !== null;
  const sortByTLabel = (n1: EntitySetting_entitySetting$data, n2: EntitySetting_entitySetting$data) => t(`entity_${n1.target_type}`).localeCompare(t(`entity_${n2.target_type}`));

  // Retrieve entitySetting with the available setting platform_entity_files_ref
  const entitySettings = usePreloadedFragment<
  EntitySettingsQuery,
  EntitySettingConnection_entitySettings$key
  >({
    linesQuery: entitySettingsQuery,
    linesFragment: entitySettingsFragment,
    queryRef,
    nodePath: 'entitySettings',
  })
    ?.edges.map((edgeNode) => (edgeNode.node))
    .map((node) => useFragment(entitySettingFragment, node) as EntitySetting_entitySetting$data)
    .filter(filterEntityFilesRef)
    .sort(sortByTLabel) ?? [];

  const [entitySettingsEntityType, setEntitySettingsEntityType] = useState<string[]>([
    ...entitySettings.filter((node) => node.platform_entity_files_ref).map((node) => node.target_type),
  ]);

  const [commit] = useMutation(entitySettingsPatch);

  const handleChange = (values: string[]) => {
    const added = values.filter((x) => !entitySettingsEntityType.includes(x));
    const removed = entitySettingsEntityType.filter((x) => !values.includes(x));

    let entitySettingId;
    let value;

    if (added.length > 0) {
      [entitySettingId] = entitySettings.filter((el) => added.includes(el.target_type)).map((node) => node.id);
      value = true.toString();
    } else if (removed.length > 0) {
      [entitySettingId] = entitySettings.filter((el) => removed.includes(el.target_type)).map((node) => node.id);
      value = false.toString();
    }
    commit({
      variables: {
        id: entitySettingId,
        input: { key: 'platform_entity_files_ref', value },
      },
    });

    setEntitySettingsEntityType(values);
  };

  return (
    <Field
      component={SelectField}
      variant="standard"
      name="platform_entities_files_ref"
      label={t('Entities automatic reference from files')}
      fullWidth={true}
      multiple={true}
      containerstyle={{ marginTop: 20, width: '100%' }}
      value={entitySettingsEntityType}
      onChange={(_: string, values: string[]) => handleChange(values)}
      renderValue={(selected: string[]) => (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
          {selected.map((value) => (
            <Chip key={value} label={t(`entity_${value}`)} />
          ))}
        </Box>
      )}>
      {entitySettings.map((entitySetting) => (
        <MenuItem key={entitySetting.target_type}
                  value={entitySetting.target_type}
                  dense={true}>
          <Checkbox checked={entitySettingsEntityType.indexOf(entitySetting.target_type) > -1} />
          {t(`entity_${entitySetting.target_type}`)}
        </MenuItem>
      ))}
    </Field>
  );
};

export default AutomaticTypesList;
