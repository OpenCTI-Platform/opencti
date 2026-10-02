import { useEffect, useRef, useState } from 'react';
import { useFragment } from 'react-relay';
import { Chip, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@filigran/design-system';
import { Box } from '@mui/material';
import { styled } from '@mui/material/styles';
import { Field, Form, Formik, FormikHelpers, FormikErrors } from 'formik';
import Dialog from '../../../../components/common/dialog/Dialog';
import Button from '../../../../components/common/button/Button';
import ItemStatus from '../../../../components/ItemStatus';
import TextareaField from '../../../../components/TextareaField';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useAuth from '../../../../utils/hooks/useAuth';
import { isBypassUser } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import { COMMENT_MAX_LENGTH, workflowBypassStatusesQuery, workflowSetStatusMutation, workflowStatusStixDomainObjectFragment } from './WorkflowStatus.graphql';
import { isWorkflowUiEnabledForType } from './workflowFeatureFlag';
import type { WorkflowStatusStixDomainObject_data$data, WorkflowStatusStixDomainObject_data$key } from './__generated__/WorkflowStatusStixDomainObject_data.graphql';
import type { WorkflowStatusBypassStatusesQuery } from './__generated__/WorkflowStatusBypassStatusesQuery.graphql';
import type { WorkflowStatusSetStatusMutation } from './__generated__/WorkflowStatusSetStatusMutation.graphql';
import ObjectOrganizationField from '../form/ObjectOrganizationField';

interface BypassValues {
  targetStatusId: string;
  applyTransitionActions: boolean;
  comment: string;
  shareOrganizations: Array<{ value: string; label?: string }>;
  unshareOrganizations: Array<{ value: string; label?: string }>;
}

type WorkflowStatus = NonNullable<WorkflowStatusStixDomainObject_data$data['workflowInstance']>['currentStatus'];

const WorkflowOrderChip = styled(Chip)({ '& > span': { color: 'inherit' } });

const ItemStatusWorkflow = ({ status }: { status: WorkflowStatus }) => (
  <>
    {status?.template && (
      <WorkflowOrderChip
        label={String(status.order + 1)}
        style={{
          color: status.template.color,
          backgroundColor: `color-mix(in srgb, ${status.template.color} 10%, transparent)`,
          marginRight: 10,
        }}
      />
    )}
    <ItemStatus status={status} />
  </>
);

export const WorkflowBypassStatus = ({ data, entityType, refreshing = false, onCompleted }: {
  data: WorkflowStatusStixDomainObject_data$key;
  entityType: string;
  refreshing?: boolean;
  onCompleted?: () => void;
}) => {
  const { t_i18n } = useFormatter();
  const { me } = useAuth();
  const { isFeatureEnable } = useHelper();
  const entity = useFragment(workflowStatusStixDomainObjectFragment, data);
  const [open, setOpen] = useState(false);
  const [targetStatusId, setTargetStatusId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [statuses, setStatuses] = useState<WorkflowStatusBypassStatusesQuery['response']['workflowBypassStatuses']>([]);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState(false);
  const [awaitingCompletion, setAwaitingCompletion] = useState(false);
  const submitting = useRef(false);
  const [commit, committing] = useApiMutation<WorkflowStatusSetStatusMutation>(workflowSetStatusMutation);
  const pendingStatus = entity.workflowInstance?.pendingStatus;
  const enabled = isBypassUser(me) && isWorkflowUiEnabledForType(entityType, isFeatureEnable) && !!entity.workflowInstance;
  const blocked = committing || saving || refreshing || awaitingCompletion || pendingStatus === 'pending' || pendingStatus === 'error';
  const currentStatus = entity.workflowInstance?.currentStatus;

  useEffect(() => {
    setAwaitingCompletion(false);
  }, [pendingStatus]);

  useEffect(() => {
    setTargetStatusId(null);
  }, [entity.id, entity.workflowInstance?.currentState, currentStatus?.id, enabled]);

  useEffect(() => {
    if (!open || !enabled) return undefined;
    let active = true;
    setLoading(true);
    setLoadError(false);
    setStatuses([]);
    fetchQuery<WorkflowStatusBypassStatusesQuery>(workflowBypassStatusesQuery, { entityId: entity.id }).toPromise()
      .then((response) => {
        if (active) setStatuses(response?.workflowBypassStatuses ?? []);
      })
      .catch(() => {
        if (active) {
          setLoadError(true);
          setOpen(false);
          MESSAGING$.notifyError(t_i18n('Unable to load workflow statuses'));
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [open, enabled, entity.id, entity.workflowInstance?.currentState]);

  if (!enabled) return null;

  const validateValues = (values: BypassValues): FormikErrors<BypassValues> => {
    const errors: FormikErrors<BypassValues> = {};
    const selected = statuses.find(({ status }) => status.id === values.targetStatusId);
    if (!selected) errors.targetStatusId = t_i18n('This field is required');
    if (values.applyTransitionActions && selected?.requiresShareOrganizationInput && values.shareOrganizations.length === 0) {
      errors.shareOrganizations = t_i18n('This field is required');
    }
    if (values.applyTransitionActions && selected?.requiresUnshareOrganizationInput && values.unshareOrganizations.length === 0) {
      errors.unshareOrganizations = t_i18n('This field is required');
    }
    return errors;
  };

  const handleApply = (values: BypassValues, helpers?: Pick<FormikHelpers<BypassValues>, 'setSubmitting'>) => {
    if (submitting.current || blocked || loading || loadError || values.comment.length > COMMENT_MAX_LENGTH
      || Object.keys(validateValues(values)).length > 0) {
      helpers?.setSubmitting(false);
      return;
    }
    submitting.current = true;
    setSaving(true);
    const release = () => {
      submitting.current = false;
      setSaving(false);
      helpers?.setSubmitting(false);
    };
    const selected = statuses.find(({ status }) => status.id === values.targetStatusId);
    const runtimeParams: Record<string, string[]> = {};
    if (values.applyTransitionActions && selected?.requiresShareOrganizationInput) {
      runtimeParams.shareOrganizationIds = values.shareOrganizations.map((organization) => organization.value);
    }
    if (values.applyTransitionActions && selected?.requiresUnshareOrganizationInput) {
      runtimeParams.unshareOrganizationIds = values.unshareOrganizations.map((organization) => organization.value);
    }
    commit({
      variables: {
        entityId: entity.id,
        targetStatusId: values.targetStatusId,
        applyTransitionActions: values.applyTransitionActions,
        comment: values.comment.trim() || undefined,
        ...(Object.keys(runtimeParams).length > 0 ? { runtimeParams } : {}),
      },
      onCompleted: (response, errors) => {
        release();
        const result = response.setWorkflowStatus;
        if (errors?.length || !result?.success) {
          MESSAGING$.notifyError(result?.reason ?? errors?.[0].message ?? t_i18n('Status update failed'));
          return;
        }
        const pending = result.executionStatus === 'pending';
        setAwaitingCompletion(pending && !onCompleted);
        onCompleted?.();
        MESSAGING$.notifySuccess(t_i18n(pending ? 'Transition started in background' : 'Status updated'));
        setOpen(false);
        setTargetStatusId(null);
      },
      onError: release,
    });
  };

  const actionLabels = (actions: WorkflowStatusBypassStatusesQuery['response']['workflowBypassStatuses'][number]['onExit']): string[] => {
    const labels: Record<string, string> = {
      updateAuthorizedMembers: t_i18n('Update authorized members'),
      validateDraft: t_i18n('Validate draft'),
      SHARE: t_i18n('Share with organizations'),
      UNSHARE: t_i18n('Unshare from organizations'),
      log: t_i18n('Log'),
    };
    return actions.flatMap((action) => {
      if (action.type !== 'asyncBulkAction') return [labels[action.type] ?? action.type];
      const params = typeof action.params === 'string' ? JSON.parse(action.params) : action.params;
      const innerActions: { type: string }[] = params?.actions ?? [];
      return innerActions.length > 0 ? innerActions.map((innerAction) => labels[innerAction.type] ?? innerAction.type) : [action.type];
    });
  };

  return (
    <>
      <Select
        value={currentStatus?.id ?? ''}
        open={open}
        onOpenChange={setOpen}
        disabled={blocked}
        onValueChange={(statusId) => {
          const selected = statuses.find(({ status }) => status.id === statusId);
          if (!selected || blocked || loading || loadError || statusId === currentStatus?.id) return;
          if (selected.onExit.length > 0 || selected.onEnter.length > 0) setTargetStatusId(statusId);
          else handleApply({ targetStatusId: statusId, applyTransitionActions: false, comment: '', shareOrganizations: [], unshareOrganizations: [] });
        }}
      >
        <SelectTrigger aria-label={t_i18n('Status')} className="h-8 w-auto max-w-full border-0 bg-transparent">
          <SelectValue><ItemStatusWorkflow status={currentStatus} /></SelectValue>
        </SelectTrigger>
        <SelectContent>
          {loading && <div role="status" className="px-3 py-2">{t_i18n('Loading')}</div>}
          {!loading && !loadError && statuses.length === 0 && <div role="status" className="px-3 py-2">{t_i18n('No available status')}</div>}
          {!loading && !loadError && statuses.map(({ status }) => (
            <SelectItem key={status.id} value={status.id} disabled={status.id === currentStatus?.id} className="px-3 py-2">
              <ItemStatusWorkflow status={status} />
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {loadError && !open && <Button variant="secondary" disabled={blocked} onClick={() => setOpen(true)}>{t_i18n('Retry')}</Button>}
      {targetStatusId && (
        <Formik<BypassValues>
          key={targetStatusId}
          initialValues={{ targetStatusId, applyTransitionActions: true, comment: '', shareOrganizations: [], unshareOrganizations: [] }}
          validate={validateValues}
          validateOnMount
          onSubmit={handleApply}
        >
          {({ values, isSubmitting, isValid, setSubmitting }) => {
            const disabled = blocked || isSubmitting;
            const dismissDisabled = committing || saving || isSubmitting;
            const selected = statuses.find(({ status }) => status.id === values.targetStatusId);
            return (
              <Dialog
                open
                title={t_i18n('Change status')}
                size="small"
                onClose={() => {
                  if (!dismissDisabled) setTargetStatusId(null);
                }}
              >
                <Form>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    <div>{t_i18n('Apply these actions when changing status?')}</div>
                    {[
                      { title: `${t_i18n('On exit actions')}: ${currentStatus?.template?.name ?? t_i18n('Unknown')}`, actions: selected?.onExit ?? [] },
                      { title: `${t_i18n('On enter actions')}: ${selected?.status.template?.name ?? t_i18n('Unknown')}`, actions: selected?.onEnter ?? [] },
                    ].filter(({ actions }) => actions.length > 0).map(({ title, actions }) => (
                      <div key={title}>
                        <strong>{title}</strong>
                        <Box component="ul" sx={{ m: 0, mt: 1, pl: 3, overflowWrap: 'anywhere' }}>
                          {actionLabels(actions).map((label, index) => <li key={`${index}-${label}`}>{label}</li>)}
                        </Box>
                      </div>
                    ))}
                    <Field component={TextareaField} name="comment" label={t_i18n('Comment')} rows={3} maxLength={COMMENT_MAX_LENGTH} disabled={disabled} helperText={`${values.comment.length} / ${COMMENT_MAX_LENGTH}`} />
                    {values.applyTransitionActions && selected?.requiresShareOrganizationInput && (
                      <ObjectOrganizationField name="shareOrganizations" label={t_i18n('Organizations to share with')} multiple disabled={disabled} style={{ width: '100%' }} />
                    )}
                    {values.applyTransitionActions && selected?.requiresUnshareOrganizationInput && (
                      <ObjectOrganizationField name="unshareOrganizations" label={t_i18n('Organizations to unshare from')} multiple disabled={disabled} style={{ width: '100%' }} />
                    )}
                  </Box>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'flex-end', gap: 1, mt: 2 }}>
                    <Button variant="tertiary" disabled={dismissDisabled} onClick={() => setTargetStatusId(null)}>{t_i18n('Cancel')}</Button>
                    <Button variant="secondary" disabled={disabled || values.comment.length > COMMENT_MAX_LENGTH} onClick={() => handleApply({ ...values, applyTransitionActions: false }, { setSubmitting })}>{t_i18n('Change status only')}</Button>
                    <Button type="submit" disabled={disabled || loading || loadError || !isValid || values.comment.length > COMMENT_MAX_LENGTH}>{t_i18n('Apply actions')}</Button>
                  </Box>
                </Form>
              </Dialog>
            );
          }}
        </Formik>
      )}
    </>
  );
};

export default WorkflowBypassStatus;
