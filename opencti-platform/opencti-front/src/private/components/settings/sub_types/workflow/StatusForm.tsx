import { useFormikContext } from 'formik';
import { useFormatter } from '../../../../../components/i18n';
import StatusTemplateField from '@components/common/form/StatusTemplateField';
import { WorkflowEditionFormValues } from './WorkflowEditionDrawer';
import { Box, FormControlLabel, Switch, Typography } from '@mui/material';
import { Alert, Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue, Switch as DsSwitch } from '@filigran/design-system';
import WorkflowFieldList from './WorkflowFieldList';
import { FEATURE_NAME, REQUEST_ACCESS_AUTHOR_KEY, RequestAccessOutcome, withoutShareRequestedEntities, WorkflowActionType, WorkflowDataType } from './utils';
import type { WorkflowScope } from '../SubTypeWorkflow';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';
import EEChip from '../../../common/entreprise_edition/EEChip';
import { AUTHORIZED_MEMBERS_ENTITY_TYPES } from '../../../../../utils/authorizedMembers';

// The library Select has no empty item, so "None" is a value of its own.
const NO_OUTCOME = 'NONE';

const StatusForm = ({ entityType, scope }: { entityType: string; scope?: WorkflowScope }) => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { values, setFieldValue } = useFormikContext<WorkflowEditionFormValues>();
  const isRequestAccess = scope === 'REQUEST_ACCESS';
  const isApprovedOutcome = isRequestAccess && values.requestAccessOutcome === 'APPROVED';
  const supportsAuthorizedMembers = AUTHORIZED_MEMBERS_ENTITY_TYPES.includes(entityType);
  const hasShareRequestedEntitiesOnEnter = values.onEnter?.some((a) => a.type === WorkflowActionType.shareRequestedEntities);
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

  const buildShareRequestedEntitiesAction = () => ({
    type: WorkflowActionType.shareRequestedEntities,
    params: { organizations: [{ value: REQUEST_ACCESS_AUTHOR_KEY, label: t_i18n('Author (requesting organization)') }] },
  });

  const handleToggleShareRequestedEntities = (checked: boolean) => {
    const currentActions = values.onEnter ?? [];
    if (checked) {
      setFieldValue('onEnter', [...currentActions, buildShareRequestedEntitiesAction()]);
    } else {
      setFieldValue('onEnter', currentActions.filter((a) => a.type !== WorkflowActionType.shareRequestedEntities));
    }
  };

  // Approving shares the requested entities: the action is added when missing. Any other outcome takes it back.
  const handleOutcomeChange = (value: string) => {
    const outcome = value === NO_OUTCOME ? null : value as RequestAccessOutcome;
    setFieldValue('requestAccessOutcome', outcome);
    if (outcome === 'APPROVED' && !hasShareRequestedEntitiesOnEnter) {
      setFieldValue('onEnter', [...(values.onEnter ?? []), buildShareRequestedEntitiesAction()]);
    } else if (outcome !== 'APPROVED' && hasShareRequestedEntitiesOnEnter) {
      setFieldValue('onEnter', withoutShareRequestedEntities(values.onEnter));
    }
  };

  const outcomeBookkeeping = {
    APPROVED: t_i18n('Entering this state sets the request status to Approved and notifies the applicant.'),
    DECLINED: t_i18n('Entering this state sets the request status to Declined and notifies the applicant.'),
  };

  return (
    <>
      <StatusTemplateField
        name="statusTemplate"
        label="Status"
        setFieldValue={(field, { value, label, color }) => setFieldValue(field, { id: value, name: label, color })}
        helpertext=""
      />
      {isRequestAccess && (
        <Box data-testid="workflow-status-outcome-container" sx={{ display: 'flex', flexDirection: 'column', gap: 1, marginTop: 1 }}>
          <Select value={values.requestAccessOutcome ?? NO_OUTCOME} onValueChange={handleOutcomeChange}>
            <SelectLabel>{t_i18n('Request outcome')}</SelectLabel>
            <SelectTrigger className="w-full" aria-label={t_i18n('Request outcome')} data-testid="workflow-status-outcome-select">
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Request outcome')}>
              <SelectItem value={NO_OUTCOME}>{t_i18n('None')}</SelectItem>
              <SelectItem value="APPROVED">{t_i18n('Approved')}</SelectItem>
              <SelectItem value="DECLINED">{t_i18n('Declined')}</SelectItem>
            </SelectContent>
          </Select>
          {values.requestAccessOutcome && (
            <Alert severity="info" title={outcomeBookkeeping[values.requestAccessOutcome]} data-testid="workflow-status-outcome-bookkeeping" />
          )}
        </Box>
      )}
      {(supportsAuthorizedMembers || isApprovedOutcome) && (
        <Box data-testid="workflow-status-onenter-actions-container" sx={{ display: 'flex', flexDirection: 'column', gap: 1, marginTop: 1 }}>
          <Typography variant="h6">
            {t_i18n('On enter actions')} <EEChip feature={t_i18n(FEATURE_NAME)} />
          </Typography>
          {supportsAuthorizedMembers && (
            <>
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
              {hasUpdateAuthorizedMembersOnEnter && <WorkflowFieldList name={WorkflowDataType.onEnter} actionType={WorkflowActionType.updateAuthorizedMembers} />}
            </>
          )}
          {isApprovedOutcome && (
            <>
              <DsSwitch
                label={t_i18n('Share requested entities on enter')}
                checked={hasShareRequestedEntitiesOnEnter}
                disabled={!isEnterpriseEdition}
                onCheckedChange={handleToggleShareRequestedEntities}
                data-testid="workflow-status-onenter-share-requested-entities-toggle"
              />
              {hasShareRequestedEntitiesOnEnter && <WorkflowFieldList name={WorkflowDataType.onEnter} actionType={WorkflowActionType.shareRequestedEntities} />}
            </>
          )}
        </Box>
      )}
      {supportsAuthorizedMembers && (
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
      )}
    </>
  );
};

export default StatusForm;
