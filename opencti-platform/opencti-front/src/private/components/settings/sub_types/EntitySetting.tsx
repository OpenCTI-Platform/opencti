import { graphql, PreloadedQuery, useFragment, useMutation, usePreloadedQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import Switch from '@mui/material/Switch';
import Grid from '@mui/material/Grid';
import { Tooltip } from '@mui/material';
import FormControlLabel from '@mui/material/FormControlLabel';
import FormGroup from '@mui/material/FormGroup';
import { InformationOutline } from 'mdi-material-ui';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import { SecurityOutlined } from '@mui/icons-material';
import ListItemText from '@mui/material/ListItemText';
import { useFormatter } from '../../../../components/i18n';
import { EntitySetting_entitySetting$key } from './__generated__/EntitySetting_entitySetting.graphql';
import { EntitySettingsRolesHiddenTypesQuery } from './__generated__/EntitySettingsRolesHiddenTypesQuery.graphql';
import { isEmptyField } from '../../../../utils/utils';
import { SubType_subType$data } from './__generated__/SubType_subType.graphql';
import ErrorNotFound from '../../../../components/ErrorNotFound';

export const entitySettingsFragment = graphql`
  fragment EntitySettingConnection_entitySettings on EntitySettingConnection {
    edges {
      node {
        id
        enforce_reference
        platform_entity_files_ref
        platform_hidden_type
        target_type
        mandatoryAttributes
        scaleAttributes {
          name
          scale
        }
      }
    }
  }
`;

// used only for entity settings configuration
export const entitySettingFragment = graphql`
  fragment EntitySetting_entitySetting on EntitySetting {
    id
    target_type
    platform_entity_files_ref
    platform_hidden_type
    enforce_reference
    attributesDefinitions {
      name
      label
      mandatory
      mandatoryType
      scale
    }
    attributes_configuration
    availableSettings
  }
`;

export const entitySettingQuery = graphql`
  query EntitySettingQuery($targetType: String!) {
    entitySettingByType(targetType: $targetType) {
      ...EntitySetting_entitySetting
    }
  }
`;

export const entitySettingsPatch = graphql`
  mutation EntitySettingsPatchMutation($ids: [ID!]!, $input: [EditInput!]!) {
    entitySettingsFieldPatch(ids: $ids, input: $input) {
      ...EntitySetting_entitySetting
    }
  }
`;

export const entitySettingsRolesHiddenTypesQuery = graphql`
    query EntitySettingsRolesHiddenTypesQuery($search: String) {
        roles(search: $search) {
            edges {
                node {
                    id
                    name
                    default_hidden_types
                }
            }
        }
    }
`;

const EntitySetting = ({
  entitySettingsData,
  roleQueryRef,
}: {
  entitySettingsData: SubType_subType$data['settings'];
  roleQueryRef: PreloadedQuery<EntitySettingsRolesHiddenTypesQuery>;
}) => {
  const { t } = useFormatter();
  const entitySetting = useFragment<EntitySetting_entitySetting$key>(entitySettingFragment, entitySettingsData);
  if (!entitySetting) {
    return <ErrorNotFound />;
  }

  const [commit] = useMutation(entitySettingsPatch);

  const handleSubmitField = (name: string, value: boolean) => {
    commit({
      variables: {
        ids: [entitySetting.id],
        input: { key: name, value: value.toString() },
      },
    });
  };
  const computeHiddenInRoles = () => {
    const data = usePreloadedQuery<EntitySettingsRolesHiddenTypesQuery>(entitySettingsRolesHiddenTypesQuery, roleQueryRef);
    const rolesData = data.roles?.edges;
    const result = [];
    if (rolesData) {
      for (const role of rolesData) {
        if (role && role.node.default_hidden_types) {
          if (role.node.default_hidden_types.includes(entitySetting.target_type)) {
            result.push(role.node);
          }
        }
      }
    }
    return result;
  };
  const hiddenInRoles = computeHiddenInRoles();
  return (
    <Grid container={true} spacing={3}>
      <Grid item={true} xs={6}>
        <div>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ float: 'left' }}
          >
            {t('Hidden in interface')}
          </Typography>
          <Tooltip
            title={
              !entitySetting.availableSettings.includes('platform_hidden_type')
                ? t('This configuration is not available for this entity type')
                : t(
                  'This configuration hide a specific entity type across the entire platform.',
                )
            }
          >
            <InformationOutline
              fontSize="small"
              color="primary"
              style={{ cursor: 'default', margin: '-2px 0 0 10px' }}
            />
          </Tooltip>
          <div className="clearfix" />
          <FormGroup>
            <FormControlLabel
              control={
                <Switch
                  disabled={
                    !entitySetting.availableSettings.includes(
                      'platform_hidden_type',
                    )
                  }
                  checked={entitySetting.platform_hidden_type ?? false}
                  onChange={() => handleSubmitField(
                    'platform_hidden_type',
                    !entitySetting.platform_hidden_type,
                  )
                  }
                />
              }
              label={t('Hide in the platform')}
            />
          </FormGroup>
        </div>
        <div style={{ marginTop: 20 }}>
          <Typography
            variant="h3"
            gutterBottom={true}
          >
            {t('Hidden in roles')}
          </Typography>
          <List>
            {hiddenInRoles.map((role) => (
              <ListItem
                key={role.id}
                dense={true}
                divider={true}
                button={true}
                component={Link}
                to={`/dashboard/settings/accesses/roles/${role.id}`}
              >
                <ListItemIcon>
                  <SecurityOutlined color="primary" />
                </ListItemIcon>
                <ListItemText primary={role.name} />
              </ListItem>
            ))}
            {isEmptyField(hiddenInRoles) && <div>{'-'}</div>}
          </List>
        </div>
      </Grid>
      <Grid item={true} xs={6}>
        <div>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ float: 'left' }}
          >
            {t('Automatic references at file upload')}
          </Typography>
          <Tooltip
            title={
              !entitySetting.availableSettings.includes(
                'platform_entity_files_ref',
              )
                ? t('This configuration is not available for this entity type')
                : t(
                  'This configuration enables an entity to automatically construct an external reference from the uploaded file.',
                )
            }
          >
            <InformationOutline
              fontSize="small"
              color="primary"
              style={{ cursor: 'default', margin: '-2px 0 0 10px' }}
            />
          </Tooltip>
          <div className="clearfix" />
          <FormGroup>
            <FormControlLabel
              control={
                <Switch
                  disabled={
                    !entitySetting.availableSettings.includes(
                      'platform_entity_files_ref',
                    )
                  }
                  checked={entitySetting.platform_entity_files_ref ?? false}
                  onChange={() => handleSubmitField(
                    'platform_entity_files_ref',
                    !entitySetting.platform_entity_files_ref,
                  )
                  }
                />
              }
              label={t('Create external reference at upload')}
            />
          </FormGroup>
        </div>
        <div style={{ marginTop: 20 }}>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ float: 'left' }}
          >
            {t('Enforce reference')}
          </Typography>
          <Tooltip
            title={
              !entitySetting.availableSettings.includes('enforce_reference')
                ? t('This configuration is not available for this entity type')
                : t(
                  'This configuration enables the requirement of a reference message on an entity creation or modification.',
                )
            }
          >
            <InformationOutline
              fontSize="small"
              color="primary"
              style={{ cursor: 'default', margin: '-2px 0 0 10px' }}
            />
          </Tooltip>
          <div className="clearfix" />
          <FormGroup>
            <FormControlLabel
              control={
                <Switch
                  disabled={
                    !entitySetting.availableSettings.includes(
                      'enforce_reference',
                    )
                  }
                  checked={entitySetting.enforce_reference ?? false}
                  onChange={() => handleSubmitField(
                    'enforce_reference',
                    !entitySetting.enforce_reference,
                  )
                  }
                />
              }
              label={t('Enforce references')}
            />
          </FormGroup>
        </div>
      </Grid>
    </Grid>
  );
};

export default EntitySetting;
