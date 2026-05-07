import { Field, useFormikContext } from 'formik';
import TextField from '../../../../../components/TextField';
import { useFormatter } from '../../../../../components/i18n';
import WorkflowFieldList from './WorkflowFieldList';
import { WorkflowActionType, WorkflowDataType } from './utils';
import { FormControlLabel, Icon, Switch, Typography, Box } from '@mui/material';
import { WorkflowEditionFormValues } from './WorkflowEditionDrawer';
import { FlagOutlined } from '@mui/icons-material';
import WorkflowConditionFilters from './WorkflowConditionFilters';

const TransitionForm = () => {
  const { t_i18n } = useFormatter();
  const { values, setFieldValue } = useFormikContext<WorkflowEditionFormValues>();
  const hasUpdateAuthorizedMembers = values.actions?.some((a) => a.type === WorkflowActionType.updateAuthorizedMembers);
  const hasValidateDraft = values.actions?.some((a) => a.type === WorkflowActionType.validateDraft);
  const hasAsyncBulkAction = values.asyncActions?.some((a) => a.type === WorkflowActionType.asyncBulkAction);

  const handleToggleAction = (actionType: WorkflowActionType, checked: boolean) => {
    const currentActions = values.actions ?? [];
    if (checked) {
      const newAction = actionType === WorkflowActionType.updateAuthorizedMembers
        ? { type: actionType, params: { authorized_members: [] } }
        : { type: actionType };
      setFieldValue('actions', [...currentActions, newAction]);
    } else {
      setFieldValue('actions', currentActions.filter((a) => a.type !== actionType));
    }
  };

  const handleToggleAsyncBulkAction = (checked: boolean) => {
    const currentAsync = values.asyncActions ?? [];
    if (checked) {
      setFieldValue('asyncActions', [...currentAsync, { type: WorkflowActionType.asyncBulkAction, mode: 'async', params: { scope: 'KNOWLEDGE', actions: [], failOnAnyError: true } }]);
    } else {
      setFieldValue('asyncActions', currentAsync.filter((a) => a.type !== WorkflowActionType.asyncBulkAction));
    }
  };

  return (
    <>
      <Field component={TextField} variant="standard" name="event" label={t_i18n('Transition name')} fullWidth />

      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, marginTop: 2 }}>
        <Typography variant="h6">
          {t_i18n('Conditions')}
        </Typography>
        {values.conditions && <Field name={WorkflowDataType.conditions} component={WorkflowConditionFilters} />}
      </Box>

      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, marginTop: 1 }}>
        <Typography variant="h6">
          {t_i18n('Async actions (phase 1)')}
        </Typography>
        <Box sx={{ display: 'flex', flexDirection: 'column' }}>
          <FormControlLabel
            control={(
              <Switch
                checked={hasAsyncBulkAction}
                onChange={(e) => handleToggleAsyncBulkAction(e.target.checked)}
              />
            )}
            label={t_i18n('Async bulk action (background task)')}
          />
          {hasAsyncBulkAction && (
            <FormControlLabel
              sx={{ pl: 4 }}
              control={(
                <Switch
                  checked={values.requiresOrganizationInput ?? false}
                  onChange={(e) => setFieldValue('requiresOrganizationInput', e.target.checked)}
                />
              )}
              label={t_i18n('Requires organization input at trigger time')}
            />
          )}
        </Box>
      </Box>

      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, marginTop: 1 }}>
        <Typography variant="h6">
          {t_i18n('Sync actions (phase 2)')}
        </Typography>
        <Box sx={{ display: 'flex', flexDirection: 'column' }}>
          <FormControlLabel
            control={(
              <Switch
                checked={hasUpdateAuthorizedMembers}
                onChange={(e) => handleToggleAction(WorkflowActionType.updateAuthorizedMembers, e.target.checked)}
              />
            )}
            label={t_i18n('Update authorized members')}
          />
          {values.actions && <WorkflowFieldList name={WorkflowDataType.actions} />}

          <FormControlLabel
            control={(
              <Switch
                checked={hasValidateDraft}
                onChange={(e) => handleToggleAction(WorkflowActionType.validateDraft, e.target.checked)}
              />
            )}
            label={(
              <Box style={{ display: 'flex', alignItems: 'center' }}>
                {t_i18n('Validate draft')}
                <Icon color="primary" fontSize="small" style={{ marginLeft: 8 }}><FlagOutlined /></Icon>
              </Box>
            )}
          />
        </Box>
      </Box>
    </>
  );
};

export default TransitionForm;
