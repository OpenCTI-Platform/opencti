import { Box, Button, TextField, Tooltip } from '@mui/material';
import FormControlLabel from '@mui/material/FormControlLabel';
import FormGroup from '@mui/material/FormGroup';
import Grid from '@mui/material/Grid';
import Switch from '@mui/material/Switch';
import { InformationOutline } from 'mdi-material-ui';
import { graphql, useFragment } from 'react-relay';
import { useState } from 'react';
import Label from '../../../../../components/common/label/Label';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { SETTINGS_SETACCESSES } from '../../../../../utils/hooks/useGranted';
import Security from '../../../../../utils/Security';
import GroupEntitySettingHiddenTypesList from '../../groups/GroupEntitySettingHiddenTypesList';
import SettingsOrganizationEntitySettingHiddenTypesList from '../../organizations/SettingsOrganizationEntitySettingHiddenTypesList';
import { EntitySettingSettings_entitySetting$key } from './__generated__/EntitySettingSettings_entitySetting.graphql';

export const entitySettingFragment = graphql`
  fragment EntitySettingSettings_entitySetting on EntitySetting {
    id
    target_type
    platform_entity_files_ref
    platform_hidden_type
    enforce_reference
    availableSettings
    mandatoryAttributes
    scaleAttributes {
      name
      scale
    }
    defaultValuesAttributes {
      name
      type
      defaultValues {
        id
        name
      }
    }
    overview_layout_customization {
        key
        width
        label
    }
    requestAccessConfiguration {
        id
        approval_admin {
            id
            name
        }
        declined_status {
            id
            template {
                id
                name
                color
            }
        }
        approved_status {
            template {
                id
                name
                color
            }
        }
    }
    custom_name
    custom_name_plural
  }
`;

export const entitySettingPatch = graphql`
  mutation EntitySettingSettingsPatchMutation(
    $ids: [ID!]!
    $input: [EditInput!]!
  ) {
    entitySettingsFieldPatch(ids: $ids, input: $input) {
      ...EntitySettingSettings_entitySetting
    }
  }
`;

interface EntitySettingSettingsProps {
  entitySettingsData: EntitySettingSettings_entitySetting$key;
}

const EntitySettingSettings = ({ entitySettingsData }: EntitySettingSettingsProps) => {
  const { t_i18n } = useFormatter();
  const entitySetting = useFragment(entitySettingFragment, entitySettingsData);
  if (!entitySetting) {
    return <ErrorNotFound />;
  }

  const [commit] = useApiMutation(entitySettingPatch);

  const [customName, setCustomName] = useState(entitySetting.custom_name ?? '');
  const [customNamePlural, setCustomNamePlural] = useState(entitySetting.custom_name_plural ?? '');

  const handleSubmitField = (name: string, value: boolean) => {
    commit({
      variables: {
        ids: [entitySetting.id],
        input: { key: name, value: value.toString() },
      },
    });
  };

  const handleSubmitCustomName = (name: string, value: string) => {
    commit({
      variables: {
        ids: [entitySetting.id],
        input: { key: name, value: [value] },
      },
    });
  };

  const handleResetCustomNames = () => {
    setCustomName('');
    setCustomNamePlural('');
    commit({
      variables: {
        ids: [entitySetting.id],
        input: [
          { key: 'custom_name', value: [''] },
          { key: 'custom_name_plural', value: [''] },
        ],
      },
    });
  };

  return (
    <Grid container={true} spacing={2}>
      <Grid item xs={6}>
        <div>
          <Label action={(
            <Tooltip
              title={!entitySetting.availableSettings.includes('platform_hidden_type')
                ? t_i18n('This configuration is not available for this entity type')
                : t_i18n('This configuration hides a specific entity type across the entire platform.')
              }
            >
              <InformationOutline
                fontSize="small"
                color="primary"
              />
            </Tooltip>
          )}
          >
            {t_i18n('Hidden in interface')}
          </Label>

          <FormGroup>
            <FormControlLabel
              control={(
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
              )}
              label={t_i18n('Hide in the platform')}
            />
          </FormGroup>
        </div>
        <Security needs={[SETTINGS_SETACCESSES]}>
          <>
            <GroupEntitySettingHiddenTypesList targetType={entitySetting.target_type} />
            <SettingsOrganizationEntitySettingHiddenTypesList targetType={entitySetting.target_type} />
          </>
        </Security>
      </Grid>
      <Grid item xs={6}>
        <div>
          <Label action={(
            <Tooltip
              title={!entitySetting.availableSettings.includes('platform_entity_files_ref')
                ? t_i18n('This configuration is not available for this entity type')
                : t_i18n('This configuration enables an entity to automatically construct an external reference from the uploaded file.')
              }
            >
              <InformationOutline
                fontSize="small"
                color="primary"
              />
            </Tooltip>
          )}
          >
            {t_i18n('Automatic references at file upload')}
          </Label>

          <FormGroup>
            <FormControlLabel
              control={(
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
              )}
              label={t_i18n('Create external reference at upload')}
            />
          </FormGroup>
        </div>
        <Box sx={{ marginTop: 2 }}>
          <Label action={(
            <Tooltip
              title={!entitySetting.availableSettings.includes('enforce_reference')
                ? t_i18n('This configuration is not available for this entity type')
                : t_i18n('This configuration enables the requirement of a reference message on an entity creation or modification.')
              }
            >
              <InformationOutline
                fontSize="small"
                color="primary"
              />
            </Tooltip>
          )}
          >
            {t_i18n('Enforce references')}
          </Label>
          <FormGroup>
            <FormControlLabel
              control={(
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
              )}
              label={t_i18n('Enforce references')}
            />
          </FormGroup>
        </Box>
      </Grid>
      <Grid item xs={12}>
        <Box sx={{ marginTop: 2 }}>
          <Label action={(
            <Tooltip
              title={t_i18n('Set a custom display name for this entity type. Leave empty to use the default name.')}
            >
              <InformationOutline
                fontSize="small"
                color="primary"
              />
            </Tooltip>
          )}
          >
            {t_i18n('Display name')}
          </Label>
          <Grid container spacing={2} sx={{ marginTop: 1 }}>
            <Grid item xs={5}>
              <TextField
                data-testid="entity-setting-custom-name-input"
                label={t_i18n('Display name (singular)')}
                fullWidth
                size="small"
                variant="outlined"
                value={customName}
                onChange={(e) => setCustomName(e.target.value)}
                onBlur={() => handleSubmitCustomName('custom_name', customName)}
                placeholder={t_i18n('e.g. Intelligence Product')}
              />
            </Grid>
            <Grid item xs={5}>
              <TextField
                data-testid="entity-setting-custom-name-plural-input"
                label={t_i18n('Display name (plural)')}
                fullWidth
                size="small"
                variant="outlined"
                value={customNamePlural}
                onChange={(e) => setCustomNamePlural(e.target.value)}
                onBlur={() => handleSubmitCustomName('custom_name_plural', customNamePlural)}
                placeholder={t_i18n('e.g. Intelligence Products')}
              />
            </Grid>
            <Grid item xs={2} sx={{ display: 'flex', alignItems: 'center' }}>
              <Button
                data-testid="entity-setting-custom-name-reset-btn"
                variant="outlined"
                size="small"
                disabled={!customName && !customNamePlural}
                onClick={handleResetCustomNames}
              >
                {t_i18n('Reset to default')}
              </Button>
            </Grid>
          </Grid>
        </Box>
      </Grid>
    </Grid>
  );
};

export default EntitySettingSettings;
