import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Typography from '@mui/material/Typography';
import Switch from '@mui/material/Switch';
import Grid from '@mui/material/Grid';
import { Tooltip } from '@mui/material';
import FormControlLabel from '@mui/material/FormControlLabel';
import FormGroup from '@mui/material/FormGroup';
import { InformationOutline } from 'mdi-material-ui';
import { useFormatter } from '../../../../../components/i18n';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import { SETTINGS_SETACCESSES } from '../../../../../utils/hooks/useGranted';
import GroupEntitySettingHiddenTypesList from '../../groups/GroupEntitySettingHiddenTypesList';
import Security from '../../../../../utils/Security';
import { EntitySettingSettings_entitySetting$key } from './__generated__/EntitySettingSettings_entitySetting.graphql';
import SettingsOrganizationEntitySettingHiddenTypesList from '../../organizations/SettingsOrganizationEntitySettingHiddenTypesList';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';

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
  entitySettingsData: EntitySettingSettings_entitySetting$key
}

const EntitySettingSettings = ({ entitySettingsData }: EntitySettingSettingsProps) => {
  const { t_i18n } = useFormatter();
  const entitySetting = useFragment(entitySettingFragment, entitySettingsData);
  if (!entitySetting) {
    return <ErrorNotFound />;
  }

  const [commit] = useApiMutation(entitySettingPatch);

  const handleSubmitField = (name: string, value: boolean) => {
    commit({
      variables: {
        ids: [entitySetting.id],
        input: { key: name, value: value.toString() },
      },
    });
  };
  return (
    <Grid container={true} spacing={3}>
      <Grid item xs={6}>
        <div>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ float: 'left' }}
          >
            {t_i18n('Hidden in interface')}
          </Typography>
          <Tooltip
            title={
              !entitySetting.availableSettings.includes('platform_hidden_type')
                ? t_i18n('This configuration is not available for this entity type')
                : t_i18n(
                  'This configuration hides a specific entity type across the entire platform.',
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
              label={t_i18n('Hide in the platform')}
            />
          </FormGroup>
        </div>
        <Security needs={[SETTINGS_SETACCESSES]}>
          <>
            <GroupEntitySettingHiddenTypesList targetType={entitySetting.target_type}></GroupEntitySettingHiddenTypesList>
            <SettingsOrganizationEntitySettingHiddenTypesList targetType={entitySetting.target_type}></SettingsOrganizationEntitySettingHiddenTypesList>
          </>
        </Security>
      </Grid>
      <Grid item xs={6}>
        <div>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ float: 'left' }}
          >
            {t_i18n('Automatic references at file upload')}
          </Typography>
          <Tooltip
            title={
              !entitySetting.availableSettings.includes(
                'platform_entity_files_ref',
              )
                ? t_i18n('This configuration is not available for this entity type')
                : t_i18n(
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
              label={t_i18n('Create external reference at upload')}
            />
          </FormGroup>
        </div>
        <div style={{ marginTop: 20 }}>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ float: 'left' }}
          >
            {t_i18n('Enforce references')}
          </Typography>
          <Tooltip
            title={
              !entitySetting.availableSettings.includes('enforce_reference')
                ? t_i18n('This configuration is not available for this entity type')
                : t_i18n(
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
              label={t_i18n('Enforce references')}
            />
          </FormGroup>
        </div>
      </Grid>
    </Grid>
  );
};

export default EntitySettingSettings;
