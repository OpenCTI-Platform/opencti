import { Box, Tooltip } from '@mui/material';
import FormControlLabel from '@mui/material/FormControlLabel';
import FormGroup from '@mui/material/FormGroup';
import Switch from '@mui/material/Switch';
import { InformationOutline } from 'mdi-material-ui';
import Label from '../../../../../components/common/label/Label';
import { useFormatter } from '../../../../../components/i18n';
import { EntitySettingsFragment_entitySetting$data } from './__generated__/EntitySettingsFragment_entitySetting.graphql';

interface EntitySettingReferencesProps {
  entitySetting: EntitySettingsFragment_entitySetting$data;
  handleSubmitField: (name: string, value: boolean) => void;
}

const EntitySettingReferences = ({
  entitySetting,
  handleSubmitField,
}: EntitySettingReferencesProps) => {
  const { t_i18n } = useFormatter();

  return (
    <>
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
    </>
  );
};

export default EntitySettingReferences;
