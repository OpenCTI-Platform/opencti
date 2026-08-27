import { useFormikContext } from 'formik';
import { useFormatter } from '../../../../../components/i18n';
import StatusTemplateField from '@components/common/form/StatusTemplateField';
import { WorkflowEditionFormValues } from './WorkflowEditionDrawer';
import { Box, FormControlLabel, Switch, Typography } from '@mui/material';
import WorkflowFieldList from './WorkflowFieldList';
import { FEATURE_NAME, WorkflowActionType, WorkflowDataType } from './utils';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';
import EEChip from '../../../common/entreprise_edition/EEChip';

const StatusForm = () => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { values, setFieldValue } = useFormikContext<WorkflowEditionFormValues>();
  const hasUpdateAuthorizedMembersOnEnter = values.onEnter?.some((a) => a.type === WorkflowActionType.updateAuthorizedMembers);
  const hasUpdateAuthorizedMembersOnExit = values.onExit?.some((a) => a.type === WorkflowActionType.updateAuthorizedMembers);

  const handleToggleUpdateAuthorizedMembers = (field: 'onEnter' | 'onExit', checked: boolean) => {
    const currentActions = values[field] ?? [];
    if (checked) {
      // Use the dynamic 'CREATORS' key (same as TransitionForm's default) rather than the
      // singular CREATOR_AUTHORIZED_CONFIG generic-option id: the latter is filtered out of
      // the AuthorizedMembersField's rendered list by isGenericOption (since showCreatorLine
      // isn't set here), making it invisible/impossible to edit or remove from the UI, and it
      // isn't a key resolveDynamicAuthorizedMembers understands server-side (only 'CREATORS' is).
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
      <Box data-testid="workflow-status-onenter-actions-container" sx={{ display: 'flex', flexDirection: 'column', gap: 1, marginTop: 1 }}>
        <Typography variant="h6">
          {t_i18n('On enter actions')} <EEChip feature={t_i18n(FEATURE_NAME)} />
        </Typography>
        <FormControlLabel
          control={(
            <Switch
              checked={hasUpdateAuthorizedMembersOnEnter}
              disabled={!isEnterpriseEdition}
              onChange={(e) => handleToggleUpdateAuthorizedMembers('onEnter', e.target.checked)}
              data-testid="workflow-status-onenter-authorized-members-toggle"
            />
          )}
          label={t_i18n('Update authorized members on enter')}
        />
        {hasUpdateAuthorizedMembersOnEnter && <WorkflowFieldList name={WorkflowDataType.onEnter} />}
      </Box>
      <Box data-testid="workflow-status-onexit-actions-container" sx={{ display: 'flex', flexDirection: 'column', gap: 1, marginTop: 1 }}>
        <Typography variant="h6">
          {t_i18n('On exit actions')} <EEChip feature={t_i18n(FEATURE_NAME)} />
        </Typography>
        <FormControlLabel
          control={(
            <Switch
              checked={hasUpdateAuthorizedMembersOnExit}
              disabled={!isEnterpriseEdition}
              onChange={(e) => handleToggleUpdateAuthorizedMembers('onExit', e.target.checked)}
              data-testid="workflow-status-onexit-authorized-members-toggle"
            />
          )}
          label={t_i18n('Update authorized members on exit')}
        />
        {hasUpdateAuthorizedMembersOnExit && <WorkflowFieldList name={WorkflowDataType.onExit} />}
      </Box>
    </>
  );
};

export default StatusForm;
