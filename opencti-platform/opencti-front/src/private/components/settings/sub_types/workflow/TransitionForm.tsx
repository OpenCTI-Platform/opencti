import { FlagOutlined } from '@mui/icons-material';
import { Alert, Box, FormControlLabel, Icon, Switch, Typography } from '@mui/material';
import { Field, useFormikContext } from 'formik';
import TextField from '../../../../../components/TextField';
import { useFormatter } from '../../../../../components/i18n';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';
import EEChip from '../../../common/entreprise_edition/EEChip';
import ObjectOrganizationField from '../../../common/form/ObjectOrganizationField';
import WorkflowConditionFilters from './WorkflowConditionFilters';
import { WorkflowEditionFormValues } from './WorkflowEditionDrawer';
import WorkflowFieldList from './WorkflowFieldList';
import { CommentMode, CommentModeType, WorkflowActionType, WorkflowDataType } from './utils';

const TransitionForm = () => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { values, setFieldValue } = useFormikContext<WorkflowEditionFormValues>();
  const hasUpdateAuthorizedMembers = values.syncActions?.some((a) => a.type === WorkflowActionType.updateAuthorizedMembers);
  const hasValidateDraft = values.syncActions?.some((a) => a.type === WorkflowActionType.validateDraft);
  const hasShare = values.asyncActions?.some((a) => a.type === WorkflowActionType.shareWithOrganizations);
  const hasUnshare = values.asyncActions?.some((a) => a.type === WorkflowActionType.unshareFromOrganizations);
  const shareIdx = values.asyncActions?.findIndex((a) => a.type === WorkflowActionType.shareWithOrganizations) ?? -1;
  const unshareIdx = values.asyncActions?.findIndex((a) => a.type === WorkflowActionType.unshareFromOrganizations) ?? -1;

  const commentMode: CommentModeType = values.comment ?? CommentMode.disabled;
  const enableComments = commentMode !== CommentMode.disabled;
  const requireComments = commentMode === CommentMode.required;

  const handleToggleEnableComments = (checked: boolean) => {
    setFieldValue('comment', checked ? CommentMode.allowed : CommentMode.disabled);
  };

  const handleToggleRequireComments = (checked: boolean) => {
    setFieldValue('comment', checked ? CommentMode.required : CommentMode.allowed);
  };

  const handleToggleAction = (actionType: WorkflowActionType, checked: boolean) => {
    const currentActions = values.syncActions ?? [];
    if (checked) {
      const newAction = actionType === WorkflowActionType.updateAuthorizedMembers
        ? { type: actionType, params: { authorized_members: [] } }
        : { type: actionType };
      setFieldValue('syncActions', [...currentActions, newAction]);
    } else {
      setFieldValue('syncActions', currentActions.filter((a) => a.type !== actionType));
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
          {t_i18n('Conditions')} <EEChip />
        </Typography>
        {values.conditions && (
          <Box style={{ opacity: isEnterpriseEdition ? 1 : 0.5, pointerEvents: isEnterpriseEdition ? 'auto' : 'none' }}>
            <Field name={WorkflowDataType.conditions} component={WorkflowConditionFilters} />
          </Box>
        )}
      </Box>

      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, marginTop: 1 }}>
        <Typography variant="h6">
          {t_i18n('Organization sharing')} <EEChip />
        </Typography>
        <Box sx={{ display: 'flex', flexDirection: 'column' }}>
          <FormControlLabel
            control={(
              <Switch
                checked={hasShare}
                disabled={!isEnterpriseEdition}
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
                disabled={!isEnterpriseEdition}
              />
            </Box>
          )}
          <FormControlLabel
            control={(
              <Switch
                checked={hasUnshare}
                disabled={!isEnterpriseEdition}
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
                disabled={!isEnterpriseEdition}
              />
            </Box>
          )}
        </Box>
      </Box>

      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, marginTop: 1 }}>
        <Typography variant="h6">
          {t_i18n('Authorized members')} <EEChip />
        </Typography>
        <Box sx={{ display: 'flex', flexDirection: 'column' }}>
          <FormControlLabel
            control={(
              <Switch
                checked={hasUpdateAuthorizedMembers}
                disabled={!isEnterpriseEdition}
                onChange={(e) => handleToggleAction(WorkflowActionType.updateAuthorizedMembers, e.target.checked)}
              />
            )}
            label={t_i18n('Update authorized members')}
          />
          {values.syncActions && (
            <Box style={{ opacity: isEnterpriseEdition ? 1 : 0.5, pointerEvents: isEnterpriseEdition ? 'auto' : 'none' }}>
              <WorkflowFieldList name={WorkflowDataType.syncActions} />
            </Box>
          )}

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

      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, marginTop: 1 }}>
        <Typography variant="h6">
          {t_i18n('Comment')} <EEChip />
        </Typography>
        <Alert severity="info" variant="outlined" style={{ opacity: isEnterpriseEdition ? 1 : 0.5 }}>
          {t_i18n('When enabled, users will be prompted to leave a comment when changing the status.')}
        </Alert>
        <Box sx={{ display: 'flex', flexDirection: 'column' }}>
          <FormControlLabel
            control={(
              <Switch
                checked={enableComments}
                onChange={(e) => handleToggleEnableComments(e.target.checked)}
                disabled={!isEnterpriseEdition}
              />
            )}
            label={t_i18n('Enable comment')}
          />
          <Box sx={{ pl: 4 }}>
            <FormControlLabel
              control={(
                <Switch
                  checked={requireComments}
                  disabled={!enableComments}
                  onChange={(e) => handleToggleRequireComments(e.target.checked)}
                />
              )}
              label={t_i18n('Required')}
            />
          </Box>
        </Box>
      </Box>
    </>
  );
};

export default TransitionForm;
