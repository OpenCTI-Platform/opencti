import { useFormikContext } from 'formik';
import { useFormatter } from '../../../../../components/i18n';
import StatusTemplateField from '@components/common/form/StatusTemplateField';
import { WorkflowEditionFormValues } from './WorkflowEditionDrawer';
import { Box, FormControlLabel, Switch, Typography } from '@mui/material';
import WorkflowFieldList from './WorkflowFieldList';
import { AUTHORIZED_MEMBERS_EXCLUSIVE_ACTIONS, FEATURE_NAME, WorkflowActionType, WorkflowDataType } from './utils';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';
import EEChip from '../../../common/entreprise_edition/EEChip';
import { AUTHORIZED_MEMBERS_ENTITY_TYPES } from '../../../../../utils/authorizedMembers';
import ItemCopy from '../../../../../components/ItemCopy';

const StatusForm = ({ entityType, workflowStatusIds = {} }: { entityType: string; workflowStatusIds?: Record<string, string> }) => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { values, setFieldValue } = useFormikContext<WorkflowEditionFormValues>();
  const hasUpdateAuthorizedMembersOnEnter = values.onEnter?.some((a) => a.type === WorkflowActionType.updateAuthorizedMembers);
  const hasUpdateAuthorizedMembersOnExit = values.onExit?.some((a) => a.type === WorkflowActionType.updateAuthorizedMembers);
  const hasResetAuthorizedMembersOnEnter = values.onEnter?.some((a) => a.type === WorkflowActionType.resetAuthorizedMembers);
  const hasResetAuthorizedMembersOnExit = values.onExit?.some((a) => a.type === WorkflowActionType.resetAuthorizedMembers);

  // The Status id only exists once the template has been published for this entity type.
  // It is looked up from the template currently selected in the form, so swapping the
  // template never shows the id of the previous one.
  const selectedTemplateId = values.statusTemplate?.id;
  const workflowStatusId = selectedTemplateId ? workflowStatusIds[selectedTemplateId] : undefined;

  const handleToggleAuthorizedMembersAction = (field: 'onEnter' | 'onExit', actionType: WorkflowActionType, checked: boolean) => {
    const currentActions = values[field] ?? [];
    if (checked) {
      // Use the dynamic 'CREATORS' key (same as TransitionForm's default) rather than the
      // singular CREATOR_AUTHORIZED_CONFIG generic-option id: the latter is filtered out of
      // the AuthorizedMembersField's rendered list by isGenericOption (since showCreatorLine
      // isn't set here), making it invisible/impossible to edit or remove from the UI, and it
      // isn't a key resolveDynamicAuthorizedMembers understands server-side (only 'CREATORS' is).
      const newAction = actionType === WorkflowActionType.updateAuthorizedMembers
        ? { type: actionType, params: { authorized_members: [{ label: 'Creators', type: 'Dynamic options', value: 'CREATORS', accessRight: 'admin' as const, groupsRestriction: [] }] } }
        : { type: actionType };
      // Update and reset of authorized members contradict each other: turning one on turns the other off
      const exclusiveType = AUTHORIZED_MEMBERS_EXCLUSIVE_ACTIONS[actionType];
      const keptActions = exclusiveType ? currentActions.filter((a) => a.type !== exclusiveType) : currentActions;
      setFieldValue(field, [...keptActions, newAction]);
    } else {
      setFieldValue(field, currentActions.filter((a) => a.type !== actionType));
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
      {selectedTemplateId && (
        <Box data-testid="workflow-status-id" sx={{ display: 'flex', flexDirection: 'column', gap: 0.5, marginTop: 1 }}>
          <Typography variant="h6">{t_i18n('Status ID')}</Typography>
          {workflowStatusId
            ? <ItemCopy content={workflowStatusId} variant="inLine" />
            : <Typography variant="body2" color="text.secondary">{t_i18n('Available after publish')}</Typography>}
        </Box>
      )}
      {AUTHORIZED_MEMBERS_ENTITY_TYPES.includes(entityType) && (
        <Box data-testid="workflow-status-onenter-actions-container" sx={{ display: 'flex', flexDirection: 'column', gap: 1, marginTop: 1 }}>
          <Typography variant="h6">
            {t_i18n('On enter actions')} <EEChip feature={t_i18n(FEATURE_NAME)} />
          </Typography>
          <FormControlLabel
            control={(
              <Switch
                checked={hasUpdateAuthorizedMembersOnEnter}
                disabled={!isEnterpriseEdition}
                onChange={(e) => handleToggleAuthorizedMembersAction('onEnter', WorkflowActionType.updateAuthorizedMembers, e.target.checked)}
                data-testid="workflow-status-onenter-authorized-members-toggle"
              />
            )}
            label={t_i18n('Update authorized members on enter')}
          />
          <FormControlLabel
            control={(
              <Switch
                checked={hasResetAuthorizedMembersOnEnter}
                disabled={!isEnterpriseEdition}
                onChange={(e) => handleToggleAuthorizedMembersAction('onEnter', WorkflowActionType.resetAuthorizedMembers, e.target.checked)}
                data-testid="workflow-status-onenter-reset-authorized-members-toggle"
              />
            )}
            label={t_i18n('Reset authorized members on enter')}
          />
          {hasUpdateAuthorizedMembersOnEnter && <WorkflowFieldList name={WorkflowDataType.onEnter} />}
        </Box>
      )}
      {AUTHORIZED_MEMBERS_ENTITY_TYPES.includes(entityType) && (
        <Box data-testid="workflow-status-onexit-actions-container" sx={{ display: 'flex', flexDirection: 'column', gap: 1, marginTop: 1 }}>
          <Typography variant="h6">
            {t_i18n('On exit actions')} <EEChip feature={t_i18n(FEATURE_NAME)} />
          </Typography>
          <FormControlLabel
            control={(
              <Switch
                checked={hasUpdateAuthorizedMembersOnExit}
                disabled={!isEnterpriseEdition}
                onChange={(e) => handleToggleAuthorizedMembersAction('onExit', WorkflowActionType.updateAuthorizedMembers, e.target.checked)}
                data-testid="workflow-status-onexit-authorized-members-toggle"
              />
            )}
            label={t_i18n('Update authorized members on exit')}
          />
          <FormControlLabel
            control={(
              <Switch
                checked={hasResetAuthorizedMembersOnExit}
                disabled={!isEnterpriseEdition}
                onChange={(e) => handleToggleAuthorizedMembersAction('onExit', WorkflowActionType.resetAuthorizedMembers, e.target.checked)}
                data-testid="workflow-status-onexit-reset-authorized-members-toggle"
              />
            )}
            label={t_i18n('Reset authorized members on exit')}
          />
          {hasUpdateAuthorizedMembersOnExit && <WorkflowFieldList name={WorkflowDataType.onExit} />}
        </Box>
      )}
    </>
  );
};

export default StatusForm;
