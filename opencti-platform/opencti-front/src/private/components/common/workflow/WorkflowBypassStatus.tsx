import { useEffect, useRef, useState } from 'react';
import { useFragment } from 'react-relay';
import {
  Chip,
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogTitle,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Text,
} from '@filigran/design-system';
import { styled } from '@mui/material/styles';
import { Form, Formik, FormikHelpers, FormikErrors } from 'formik';
import Button from '../../../../components/common/button/Button';
import ItemStatus from '../../../../components/ItemStatus';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useAuth from '../../../../utils/hooks/useAuth';
import { isBypassUser } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import { workflowBypassStatusesQuery, workflowSetStatusMutation, workflowStatusStixDomainObjectFragment } from './WorkflowStatus.graphql';
import { isWorkflowUiEnabledForType } from './workflowFeatureFlag';
import type { WorkflowStatusStixDomainObject_data$data, WorkflowStatusStixDomainObject_data$key } from './__generated__/WorkflowStatusStixDomainObject_data.graphql';
import type { WorkflowStatusBypassStatusesQuery } from './__generated__/WorkflowStatusBypassStatusesQuery.graphql';
import type { WorkflowStatusSetStatusMutation } from './__generated__/WorkflowStatusSetStatusMutation.graphql';
import { Box } from '@mui/material';

interface BypassValues {
  targetStatusId: string;
  applyTransitionActions: boolean;
}

type WorkflowStatus = NonNullable<WorkflowStatusStixDomainObject_data$data['workflowInstance']>['currentStatus'];

const WorkflowOrderChip = styled(Chip)({ '& > span': { color: 'inherit' } });

export const ItemStatusWorkflow = ({ status }: { status: WorkflowStatus }) => (
  <div className="flex gap-2">
    {status?.template && (
      <WorkflowOrderChip
        label={String(status.order + 1)}
        style={{
          color: status.template.color,
          backgroundColor: `color-mix(in srgb, ${status.template.color} 10%, transparent)`,
        }}
      />
    )}
    <ItemStatus status={status} />
  </div>
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
    return errors;
  };

  const handleApply = (values: BypassValues, helpers?: Pick<FormikHelpers<BypassValues>, 'setSubmitting'>) => {
    if (submitting.current || blocked || loading || loadError || Object.keys(validateValues(values)).length > 0) {
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
    commit({
      variables: {
        entityId: entity.id,
        targetStatusId: values.targetStatusId,
        applyTransitionActions: values.applyTransitionActions,
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

  const hasTransitionActions = (statusId: string) => {
    const selected = statuses.find(({ status }) => status.id === statusId);
    return !!selected && (selected.onExit.length > 0 || selected.onEnter.length > 0);
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
          setTargetStatusId(statusId);
        }}
      >
        <SelectTrigger aria-label={t_i18n('Status')} className="h-8 w-auto max-w-full border-0 bg-transparent">
          <SelectValue><ItemStatusWorkflow status={currentStatus} /></SelectValue>
        </SelectTrigger>
        <SelectContent aria-label={t_i18n('Status')}>
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
          initialValues={{ targetStatusId, applyTransitionActions: hasTransitionActions(targetStatusId) }}
          validate={validateValues}
          validateOnMount
          onSubmit={handleApply}
        >
          {({ values, isSubmitting, isValid, setSubmitting }) => {
            const disabled = blocked || isSubmitting;
            const dismissDisabled = committing || saving || isSubmitting;
            const selected = statuses.find(({ status }) => status.id === values.targetStatusId);
            const hasActions = hasTransitionActions(values.targetStatusId);
            return (
              <Dialog
                open
                onOpenChange={(isOpen) => {
                  if (!isOpen && !dismissDisabled) setTargetStatusId(null);
                }}
              >
                <DialogContent>
                  <DialogTitle className="flex flex-col gap-6">
                    <Text variant="title-md">{t_i18n('Update status')}</Text>

                    <div className="flex items-center gap-1">
                      <ItemStatusWorkflow status={currentStatus} />
                      →
                      <ItemStatusWorkflow status={selected?.status} />
                    </div>
                  </DialogTitle>
                  <Form className="flex flex-col gap-6 min-h-0">
                    <DialogBody style={{ margin: 'calc(var(--spacing) * -1)', padding: 'var(--spacing)' }}>
                      <Box className="flex flex-col gap-8 mb-8">
                        <DialogDescription>
                          <Text variant="content-compact">
                            {hasActions
                              ? t_i18n('Apply these actions when changing status?')
                              : t_i18n('No actions are configured for this transition. The status will be changed directly.')}
                          </Text>
                        </DialogDescription>
                        {[
                          { title: t_i18n('On exit actions'), status: currentStatus, actions: selected?.onExit ?? [] },
                          { title: t_i18n('On enter actions'), status: selected?.status, actions: selected?.onEnter ?? [] },
                        ].filter(({ actions }) => actions.length > 0).map(({ title, status, actions }) => (
                          <div key={title} className="flex flex-col gap-2">
                            <div className="flex items-center gap-2">
                              <Text variant="title-sm">{title}</Text>
                              <ItemStatus status={status} />
                            </div>
                            <ul className="m-0 mt-1 pl-6" style={{ overflowWrap: 'anywhere' }}>
                              {actionLabels(actions).map((label, index) => <li key={`${index}-${label}`}><Text variant="content-compact">{label}</Text></li>)}
                            </ul>
                          </div>
                        ))}
                      </Box>
                    </DialogBody>
                    <DialogFooter className="flex-wrap">
                      <Button variant="tertiary" disabled={dismissDisabled} onClick={() => setTargetStatusId(null)}>{t_i18n('Cancel')}</Button>
                      {hasActions && (
                        <Button variant="secondary" disabled={disabled} onClick={() => handleApply({ ...values, applyTransitionActions: false }, { setSubmitting })}>{t_i18n('Update status only')}</Button>
                      )}
                      <Button type="submit" disabled={disabled || loading || loadError || !isValid}>{t_i18n(hasActions ? 'Apply actions' : 'Update status')}</Button>
                    </DialogFooter>
                  </Form>
                </DialogContent>
              </Dialog>
            );
          }}
        </Formik>
      )}
    </>
  );
};

export default WorkflowBypassStatus;
