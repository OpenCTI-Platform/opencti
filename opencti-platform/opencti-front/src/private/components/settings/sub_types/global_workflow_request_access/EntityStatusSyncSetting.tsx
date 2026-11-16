import { Icon, Switch as DsSwitch, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { graphql } from 'react-relay';
import Label from '../../../../../components/common/label/Label';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';
import { PropsWithSx } from '../../../../../utils/props';

const entityStatusSyncSettingPatch = graphql`
  mutation EntityStatusSyncSettingPatchMutation(
    $ids: [ID!]!
    $input: [EditInput!]!
  ) {
    entitySettingsFieldPatch(ids: $ids, input: $input) {
      id
      sync_workflow_status_by_name
    }
  }
`;

/**
 * "Entity status sync" entity setting: stream synchronizations name-match incoming
 * statuses instead of dropping them. Shared by the legacy workflow card and the new
 * workflow editor page.
 */
const EntityStatusSyncSetting = ({ sx }: PropsWithSx) => {
  const { t_i18n } = useFormatter();
  const { subType } = useSubTypeOutletContext();
  const [commit] = useApiMutation(entityStatusSyncSettingPatch);

  const isAvailable = subType.settings.availableSettings.includes('sync_workflow_status_by_name');
  const isEnabled = subType.settings.sync_workflow_status_by_name ?? false;

  const handleToggle = () => {
    commit({
      variables: {
        ids: [subType.settings.id],
        input: { key: 'sync_workflow_status_by_name', value: (!isEnabled).toString() },
      },
    });
  };

  return (
    <div>
      <Label
        sx={sx}
        action={(
          <Tooltip>
            <TooltipTrigger asChild>
              <span style={{ display: 'inline-flex' }}>
                <Icon name="info" size={16} className="text-feedback-info-primary" />
              </span>
            </TooltipTrigger>
            <TooltipContent>
              {isAvailable
                ? t_i18n("When enabled, stream synchronizations will try to name-match the incoming entities' statuses with this instance's statuses, instead of dropping them.")
                : t_i18n('This configuration is not available for this entity type')}
            </TooltipContent>
          </Tooltip>
        )}
      >
        {t_i18n('Entity status sync')}
      </Label>
      <DsSwitch
        disabled={!isAvailable}
        checked={isEnabled}
        onCheckedChange={handleToggle}
        label={t_i18n("Update entities' statuses by name match")}
      />
    </div>
  );
};

export default EntityStatusSyncSetting;
