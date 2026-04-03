import { Tooltip } from '@mui/material';
import FormControlLabel from '@mui/material/FormControlLabel';
import FormGroup from '@mui/material/FormGroup';
import Switch from '@mui/material/Switch';
import { InformationOutline } from 'mdi-material-ui';
import Label from '../../../../../components/common/label/Label';
import { useFormatter } from '../../../../../components/i18n';
import { SETTINGS_SETACCESSES } from '../../../../../utils/hooks/useGranted';
import Security from '../../../../../utils/Security';
import GroupEntitySettingHiddenTypesList from '../../groups/GroupEntitySettingHiddenTypesList';
import SettingsOrganizationEntitySettingHiddenTypesList from '../../organizations/SettingsOrganizationEntitySettingHiddenTypesList';
import { EntitySettingsFragment_entitySetting$data } from './__generated__/EntitySettingsFragment_entitySetting.graphql';

interface EntitySettingVisibilityProps {
  entitySetting: EntitySettingsFragment_entitySetting$data;
  handleSubmitField: (name: string, value: boolean) => void;
}

const EntitySettingVisibility = ({
  entitySetting,
  handleSubmitField,
}: EntitySettingVisibilityProps) => {
  const { t_i18n } = useFormatter();

  return (
    <>
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
    </>
  );
};

export default EntitySettingVisibility;
