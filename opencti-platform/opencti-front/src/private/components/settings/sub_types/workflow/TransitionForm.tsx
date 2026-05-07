import { Field, useFormikContext } from 'formik';
import TextField from '../../../../../components/TextField';
import { useFormatter } from '../../../../../components/i18n';
import WorkflowFieldList from './WorkflowFieldList';
import { WorkflowActionType, WorkflowDataType } from './utils';
import { FormControlLabel, Icon, Switch, Typography, Box } from '@mui/material';
import { WorkflowEditionFormValues } from './WorkflowEditionDrawer';
import { FlagOutlined } from '@mui/icons-material';
import WorkflowConditionFilters from './WorkflowConditionFilters';
import ObjectOrganizationField from '../../../common/form/ObjectOrganizationField';

const TransitionForm = () => {
  const { t_i18n } = useFormatter();
  const { values, setFieldValue } = useFormikContext<WorkflowEditionFormValues>();
  const hasUpdateAuthorizedMembers = values.actions?.some((a) => a.type === WorkflowActionType.updateAuthorizedMembers);
  const hasValidateDraft = values.actions?.some((a) => a.type === WorkflowActionType.validateDraft);
  const hasShare = values.asyncActions?.some((a) => a.type === WorkflowActionType.shareWithOrganizations);
  const hasUnshare = values.asyncActions?.some((a) => a.type === WorkflowActionType.unshareFromOrganizations);
  const shareIdx = values.asyncActions?.findIndex((a) => a.type === WorkflowActionType.shareWithOrganizations) ?? -1;
  const unshareIdx = values.asyncActions?.findIndex((a) => a.type === WorkflowActionType.unshareFromOrganizations) ?? -1;

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

  const handleToggleAsyncAction = (actionType: WorkflowActionType, checked: boolean) => {
    const currentAsync = values.asyncActions ?? [];
    if (checked) {
      setFieldValue('asyncActions', [...currentAsync, { type: actionType, params: { organizations: [] } }]);
    } else {
      setFieldValue('asyncActions', currentAsync.filter((a) => a.type !== actionType));
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
          {t_i18n('Background tasks')}
        </Typography>
        <Box sx={{ display: 'flex', flexDirection: 'column' }}>
          <FormControlLabel
            control={(
              <Switch
                checked={hasShare}
                onChange={(e) => handleToggleAsyncAction(WorkflowActionType.shareWithOrganizations, e.target.checked)}
              />
            )}
            label={t_i18n('Share with organizations')}
          />
          {hasShare && (
            <Box sx={{ pl: 4, pb: 1 }}>
              <ObjectOrganizationField
                name={`asyncActions.${shareIdx}.params.organizations`}
                label="Organizations (empty = ask at trigger time)"
                outlined={false}
                multiple={true}
                style={{ width: '100%' }}
                alert={false}
              />
            </Box>
          )}
          <FormControlLabel
            control={(
              <Switch
                checked={hasUnshare}
                onChange={(e) => handleToggleAsyncAction(WorkflowActionType.unshareFromOrganizations, e.target.checked)}
              />
            )}
            label={t_i18n('Unshare from organizations')}
          />
          {hasUnshare && (
            <Box sx={{ pl: 4, pb: 1 }}>
              <ObjectOrganizationField
                name={`asyncActions.${unshareIdx}.params.organizations`}
                label="Organizations (empty = ask at trigger time)"
                outlined={false}
                multiple={true}
                style={{ width: '100%' }}
                alert={false}
              />
            </Box>
          )}
        </Box>
      </Box>

      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, marginTop: 1 }}>
        <Typography variant="h6">
          {t_i18n('Immediate actions')}
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
