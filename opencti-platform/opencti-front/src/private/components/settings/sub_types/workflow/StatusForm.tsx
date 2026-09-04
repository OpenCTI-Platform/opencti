import { useFormikContext } from 'formik';
import { useFormatter } from '../../../../../components/i18n';
import StatusTemplateField from '@components/common/form/StatusTemplateField';
import { WorkflowEditionFormValues } from './WorkflowEditionDrawer';
import { Box, FormControlLabel, Switch, Typography } from '@mui/material';
import WorkflowFieldList from './WorkflowFieldList';
import { FEATURE_NAME, WorkflowActionType, WorkflowDataType } from './utils';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';
import EEChip from '../../../common/entreprise_edition/EEChip';
import { AUTHORIZED_MEMBERS_ENTITY_TYPES } from '../../../../../utils/authorizedMembers';

const StatusForm = ({ entityType }: { entityType: string }) => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { values, setFieldValue } = useFormikContext<WorkflowEditionFormValues>();
  const hasUpdateAuthorizedMembersOnEnter = values.onEnter?.some((a) => a.type === WorkflowActionType.updateAuthorizedMembers);
  const hasUpdateAuthorizedMembersOnExit = values.onExit?.some((a) => a.type === WorkflowActionType.updateAuthorizedMembers);

  const handleToggleUpdateAuthorizedMembers = (field: 'onEnter' | 'onExit', checked: boolean) => {
    const currentActions = values[field] ?? [];
    if (checked) {
      const newAction = { type: WorkflowActionType.updateAuthorizedMembers, params: { authorized_members: [{ label: 'Creators', type: 'Dynamic options', value: 'CREATORS', accessRight: 'admin' as const, groupsRestriction: [] }] } };
      setFieldValue(field, [...currentActions, newAction]);
    } else {
      setFieldValue(field, currentActions.filter((a) => a.type !== WorkflowActionType.updateAuthorizedMembers));
    }
  };

  return (
    <>
      <StatusTemplateField
        name="statusTemplate"
        label="Status"
        setFieldValue={(field, { value, label, color }) => setFieldValue(field, { id: value, name: label, color })}
        helpertext=""
      />
      {AUTHORIZED_MEMBERS_ENTITY_TYPES.includes(entityType) && (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, marginTop: 1 }}>
          <Typography variant="h6">
            {t_i18n('On enter actions')} <EEChip feature={t_i18n(FEATURE_NAME)} />
          </Typography>
          <FormControlLabel
            control={(
              <Switch
                checked={hasUpdateAuthorizedMembersOnEnter}
                disabled={!isEnterpriseEdition}
                onChange={(e) => handleToggleUpdateAuthorizedMembers('onEnter', e.target.checked)}
              />
            )}
            label={t_i18n('Update authorized members on enter')}
          />
          {hasUpdateAuthorizedMembersOnEnter && <WorkflowFieldList name={WorkflowDataType.onEnter} />}
        </Box>
      )}
      {AUTHORIZED_MEMBERS_ENTITY_TYPES.includes(entityType) && (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, marginTop: 1 }}>
          <Typography variant="h6">
            {t_i18n('On exit actions')} <EEChip feature={t_i18n(FEATURE_NAME)} />
          </Typography>
          <FormControlLabel
            control={(
              <Switch
                checked={hasUpdateAuthorizedMembersOnExit}
                disabled={!isEnterpriseEdition}
                onChange={(e) => handleToggleUpdateAuthorizedMembers('onExit', e.target.checked)}
              />
            )}
            label={t_i18n('Update authorized members on exit')}
          />
          {hasUpdateAuthorizedMembersOnExit && <WorkflowFieldList name={WorkflowDataType.onExit} />}
        </Box>
      )}
    </>
  );
};

export default StatusForm;
