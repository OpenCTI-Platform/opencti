import MenuItem from '@mui/material/MenuItem';
import Checkbox from '@mui/material/Checkbox';
import React, { FunctionComponent, ReactElement, useState } from 'react';
import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import { Field } from 'formik';
import { graphql, PreloadedQuery, useMutation, usePreloadedQuery } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { entitySettingsPatch, entitySettingsRolesHiddenTypesQuery } from '../sub_types/EntitySetting';
import useEntitySettings from '../../../../utils/hooks/useEntitySettings';
import { RoleEditionOverview_role$data } from '../roles/__generated__/RoleEditionOverview_role.graphql';
import { Theme } from '../../../../components/Theme';
import {
  EntitySettingsRolesHiddenTypesQuery,
} from '../sub_types/__generated__/EntitySettingsRolesHiddenTypesQuery.graphql';

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
  ['Analysis', ['Report', 'Grouping', 'Note', 'Opinion']],
  ['Cases', ['Case']],
  ['Events', ['Incident', 'Observed-Data']],
  ['Observations', ['Indicator', 'Infrastructure']],
  ['Threats', ['Threat-Actor', 'Intrusion-Set', 'Campaign']],
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

const useStyles = makeStyles<Theme>((theme) => ({
  roleIndication: {
    fontSize: 12,
    color: theme.palette.primary.main,
  },
}));

interface EntitySettingHidden {
  id: string;
  target_type: string;
  hidden: boolean;
  group: string;
}

interface HiddenTypesListProps {
  role?: RoleEditionOverview_role$data,
  queryRef?: PreloadedQuery<EntitySettingsRolesHiddenTypesQuery>,
}

const HiddenTypesList: FunctionComponent<HiddenTypesListProps> = ({ role, queryRef }) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const entitySettings = useEntitySettings().filter(({ platform_hidden_type }) => platform_hidden_type !== null)
    .map((node) => ({
      id: node.id,
      target_type: node.target_type,
      hidden: node.platform_hidden_type ?? false,
      group: findGroupKey(node.target_type),
    }))
    .filter((entitySetting) => entitySetting.group !== undefined)
    .sort((a, b) => groupKeys.indexOf(a.group) - groupKeys.indexOf(b.group));

  const hiddenTypesWithRoles = () => {
    if (queryRef) {
      const data = usePreloadedQuery<EntitySettingsRolesHiddenTypesQuery>(entitySettingsRolesHiddenTypesQuery, queryRef);
      const rolesData = data.roles?.edges;
      let result = {} as Record<string, string[]>;
      for (const n of entitySettings) {
        result = {
          ...result,
          [n.target_type]: [],
        };
      }
      if (rolesData) {
        for (const r of rolesData) {
          if (r && r.node.default_hidden_types) {
            for (const hidden_type of r.node.default_hidden_types) {
              if (hidden_type) {
                result[hidden_type].push(r.node.name);
              }
            }
          }
        }
      }
      return result;
    }
    return undefined;
  };
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

  const mutation = role ? hiddenTypesListRoleMutationFieldPatch : entitySettingsPatch;
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
    const rolesHiddenTypes = hiddenTypesWithRoles();
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
              {rolesHiddenTypes && rolesHiddenTypes[platformHiddenType.target_type].length > 0
                && (<span className={classes.roleIndication}>
                  &emsp;
                  {`(${t('Hidden in roles')} : ${rolesHiddenTypes[platformHiddenType.target_type]})`}
                </span>)
              }
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
      containerstyle={{ marginTop: 20, width: '100%' }}
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
