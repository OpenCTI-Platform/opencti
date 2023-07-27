import MenuItem from '@mui/material/MenuItem';
import Checkbox from '@mui/material/Checkbox';
import React, { FunctionComponent, ReactElement, useState } from 'react';
import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import { Field } from 'formik';
import { graphql, useMutation } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { entitySettingPatch } from '../sub_types/entitySetting/EntitySettingSettings';
import useEntitySettings from '../../../../utils/hooks/useEntitySettings';
import { RoleEditionOverview_role$data } from '../roles/__generated__/RoleEditionOverview_role.graphql';
import { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import HiddenInRolesContainer from './HiddenInRolesContainer';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

export const hiddenTypesListRoleMutationFieldPatch = graphql`
  mutation HiddenTypesListRoleEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    roleEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        name
        default_hidden_types
      }
    }
  }
`;

export const groups = new Map<string, string[]>([
  ['Analysis', ['Report', 'Grouping', 'Note', 'Malware-Analysis']],
  ['Cases', ['Case-Incident', 'Feedback', 'Case-Rfi', 'Case-Rft', 'Task']],
  ['Events', ['stix-sighting-relationship', 'Incident', 'Observed-Data']],
  ['Observations', ['Stix-Cyber-Observable', 'Indicator', 'Infrastructure']],
  ['Threats', ['Threat-Actor-Group', 'Threat-Actor-Individual', 'Intrusion-Set', 'Campaign']],
  ['Arsenal', ['Malware', 'Channel', 'Tool', 'Vulnerability']],
  [
    'Techniques',
    [
      'Attack-Pattern',
      'Narrative',
      'Course-Of-Action',
      'Data-Component',
      'Data-Source',
    ],
  ],
  ['Entities', ['Sector', 'Event', 'Organization', 'System', 'Individual']],
  [
    'Locations',
    ['Region', 'Country', 'Administrative-Area', 'City', 'Position'],
  ],
]);
const groupKeys = Array.from(groups.keys());

export const findGroupKey = (value: string) => Array.from(groups.entries())
  .filter(({ 1: v }) => v.includes(value))
  .map(([k]) => k)[0];

const itemsFromGroup = (values: string[]) => {
  for (let i = 0; i < groupKeys.length; i += 1) {
    for (let j = 0; j < values.length; j += 1) {
      if (values[j] === groupKeys[i]) {
        // Add element when group selected
        values.splice(j, 1);
        values.push(...(groups.get(groupKeys[i]) ?? []));
      } else if (values[j] === `not-${groupKeys[i]}`) {
        // Remove element when group unselected
        values.splice(j, 1);
        // eslint-disable-next-line no-param-reassign
        values = values.filter(
          (el) => !(groups.get(groupKeys[i]) ?? []).includes(el),
        );
      }
    }
  }
  return values;
};

interface EntitySettingHidden {
  id: string;
  target_type: string;
  hidden: boolean;
  group: string;
}

interface HiddenTypesListProps {
  role?: RoleEditionOverview_role$data,
}

const HiddenTypesList: FunctionComponent<HiddenTypesListProps> = ({ role }) => {
  const { t } = useFormatter();

  const entitySettings = useEntitySettings().filter(({ platform_hidden_type }) => platform_hidden_type !== null)
    .map((node) => ({
      ...node,
      hidden: node.platform_hidden_type ?? false,
      group: findGroupKey(node.target_type),
    }))
    .filter((entitySetting) => entitySetting.group !== undefined)
    .sort((a, b) => groupKeys.indexOf(a.group) - groupKeys.indexOf(b.group));

  const entitySettingsHiddenGrouped = entitySettings.reduce(
    (entryMap, entry) => {
      const values = entryMap.get(entry.group) || [];
      values.push(entry);
      entryMap.set(entry.group, values);
      return entryMap;
    },
    new Map<string, EntitySettingHidden[]>(),
  );

  let initialEntitySettingsEntityType;
  if (role) {
    initialEntitySettingsEntityType = (role.default_hidden_types ?? []) as string[];
  } else {
    initialEntitySettingsEntityType = entitySettings.filter((node) => node.hidden).map((node) => node.target_type);
  }

  const [entitySettingsEntityType, setEntitySettingsEntityType] = useState<string[]>([
    ...initialEntitySettingsEntityType,
  ]);

  const mutation = role ? hiddenTypesListRoleMutationFieldPatch : entitySettingPatch;
  const [commit] = useMutation(mutation);

  const handleChangeGlobal = (values: string[]) => {
    const realValues = itemsFromGroup(values) ?? [];
    const added = realValues.filter(
      (x) => !entitySettingsEntityType.includes(x),
    );
    const removed = entitySettingsEntityType.filter(
      (x) => !realValues.includes(x),
    );
    let entitySettingIds: string[] = [];
    let value;
    if (added.length > 0) {
      entitySettingIds = entitySettings
        .filter((el) => added.includes(el.target_type))
        .map((node) => node.id);
      value = true.toString();
      setEntitySettingsEntityType(entitySettingsEntityType.concat(added));
    } else if (removed.length > 0) {
      entitySettingIds = entitySettings
        .filter((el) => removed.includes(el.target_type))
        .map((node) => node.id);
      value = false.toString();
      setEntitySettingsEntityType(
        entitySettingsEntityType.filter((x) => !removed.includes(x)),
      );
    }
    commit({
      variables: {
        ids: entitySettingIds,
        input: { key: 'platform_hidden_type', value },
      },
    });
  };

  const handleChangeIfRole = (values: string[]) => {
    const realValues = itemsFromGroup(values) ?? [];
    const added = realValues.filter((x) => !entitySettingsEntityType.includes(x));
    const removed = entitySettingsEntityType.filter((x) => !realValues.includes(x));

    if (added.length > 0) {
      const newEntitySettingsEntityType = entitySettingsEntityType.concat(added);
      setEntitySettingsEntityType(newEntitySettingsEntityType);
      commit({
        variables: {
          id: role?.id,
          input: { key: 'default_hidden_types', value: newEntitySettingsEntityType },
        },
      });
    } else if (removed.length > 0) {
      const newEntitySettingsEntityType = entitySettingsEntityType.filter((x) => !removed.includes(x));
      setEntitySettingsEntityType(newEntitySettingsEntityType);
      commit({
        variables: {
          id: role?.id,
          input: { key: 'default_hidden_types', value: newEntitySettingsEntityType },
        },
      });
    }
  };

  const isSelectedGroup = (group: string) => {
    return groups
      .get(group)
      ?.every((el) => entitySettingsEntityType.includes(el));
  };

  const computeItems = () => {
    const items: ReactElement[] = [];
    entitySettingsHiddenGrouped.forEach((values, key) => {
      items.push(
        <MenuItem
          key={key}
          value={isSelectedGroup(key) ? `not-${key}` : key}
          dense={true}
        >
          <Checkbox
            checked={isSelectedGroup(key)}
          />
          {t(key)}
        </MenuItem>,
      );
      (values as EntitySettingHidden[]).map((platformHiddenType) => items.push(
        <MenuItem
          key={platformHiddenType.target_type}
          value={platformHiddenType.target_type}
          dense={true}
        >
          <Checkbox
            checked={
              entitySettingsEntityType.indexOf(platformHiddenType.target_type) > -1}
            style={{ marginLeft: 10 }}
          />
          {t(`entity_${platformHiddenType.target_type}`)}
          <Security needs={[SETTINGS_SETACCESSES]}>
            <HiddenInRolesContainer
              targetTypes={entitySettings.map((n) => n.target_type)}
              platformHiddenTargetType={platformHiddenType.target_type}
            ></HiddenInRolesContainer>
          </Security>
        </MenuItem>,
      ));
    });
    return items;
  };
  return (
    <Field
      component={SelectField}
      variant="standard"
      name="platform_hidden_types"
      label={role ? t('Default hidden entity types') : t('Hidden entity types')}
      fullWidth={true}
      multiple={true}
      containerstyle={fieldSpacingContainerStyle}
      value={entitySettingsEntityType}
      onChange={(_: string, values: string[]) => (role ? handleChangeIfRole(values) : handleChangeGlobal(values))}
      renderValue={(selected: string[]) => (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
          {selected.map((value) => (
            <Chip key={value} label={t(`entity_${value}`)} />
          ))}
        </Box>
      )}
    >
      {computeItems()}
    </Field>
  );
};

export default HiddenTypesList;
