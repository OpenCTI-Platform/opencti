import React, { useEffect, useRef, useState } from 'react';
import { useFragment } from 'react-relay';
import { SwapHorizOutlined } from '@mui/icons-material';
import { Box } from '@mui/material';
import { Field, Form, Formik, FormikHelpers, FormikErrors } from 'formik';
import Dialog from '../../../../components/common/dialog/Dialog';
import Button from '../../../../components/common/button/Button';
import IconButton from '../../../../components/common/button/IconButton';
import SelectFieldFds, { SelectItem } from '../../../../components/fields/SelectFieldFds';
import SwitchField from '../../../../components/fields/SwitchField';
import TextareaField from '../../../../components/TextareaField';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useAuth from '../../../../utils/hooks/useAuth';
import { isBypassUser } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import { COMMENT_MAX_LENGTH, workflowBypassStatusesQuery, workflowSetStatusMutation, workflowStatusStixDomainObjectFragment } from './WorkflowStatus.graphql';
import { isWorkflowUiEnabledForType } from './workflowFeatureFlag';
import type { WorkflowStatusStixDomainObject_data$key } from './__generated__/WorkflowStatusStixDomainObject_data.graphql';
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
  const [statuses, setStatuses] = useState<WorkflowStatusBypassStatusesQuery['response']['workflowBypassStatuses']>([]);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState(false);
  const [reload, setReload] = useState(0);
  const [awaitingCompletion, setAwaitingCompletion] = useState(false);
  const submitting = useRef(false);
  const [commit, committing] = useApiMutation<WorkflowStatusSetStatusMutation>(workflowSetStatusMutation);
  const pendingStatus = entity.workflowInstance?.pendingStatus;
  const enabled = isBypassUser(me) && isWorkflowUiEnabledForType(entityType, isFeatureEnable) && !!entity.workflowInstance;
  const blocked = committing || refreshing || awaitingCompletion || pendingStatus === 'pending' || pendingStatus === 'error';

  useEffect(() => {
    setAwaitingCompletion(false);
  }, [pendingStatus]);

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
          MESSAGING$.notifyError(t_i18n('Unable to load workflow statuses'));
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [open, enabled, entity.id, reload]);

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

  const handleApply = (values: BypassValues, { setSubmitting }: FormikHelpers<BypassValues>) => {
    if (submitting.current || blocked || loading || loadError || values.comment.length > COMMENT_MAX_LENGTH
      || Object.keys(validateValues(values)).length > 0) {
      setSubmitting(false);
      return;
    }
    submitting.current = true;
    const release = () => {
      submitting.current = false;
      setSubmitting(false);
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
      },
      onError: release,
    });
  };

  return (
    <>
      <IconButton aria-label={t_i18n('Bypass status')} title={t_i18n('Bypass status')} disabled={blocked} onClick={() => setOpen(true)}>
        <SwapHorizOutlined fontSize="small" />
      </IconButton>
      {open && (
        <Formik<BypassValues>
          initialValues={{ targetStatusId: '', applyTransitionActions: true, comment: '', shareOrganizations: [], unshareOrganizations: [] }}
          validate={validateValues}
          validateOnMount
          onSubmit={handleApply}
        >
          {({ values, isSubmitting, isValid }) => {
            const disabled = blocked || isSubmitting;
            const dismissDisabled = committing || isSubmitting;
            const selected = statuses.find(({ status }) => status.id === values.targetStatusId);
            return (
              <Dialog
                open
                title={t_i18n('Bypass status')}
                size="small"
                onClose={() => {
                  if (!dismissDisabled) setOpen(false);
                }}
              >
                <Form>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    {loading && <div role="status">{t_i18n('Loading')}</div>}
                    {loadError && <Button variant="secondary" onClick={() => setReload((value) => value + 1)}>{t_i18n('Retry')}</Button>}
                    {!loading && !loadError && statuses.length === 0 && <div role="status">{t_i18n('No available status')}</div>}
                    <Field component={SelectFieldFds} name="targetStatusId" label={t_i18n('Status')} fullWidth disabled={disabled || loading || loadError || statuses.length === 0}>
                      {statuses.map(({ status }) => <SelectItem key={status.id} value={status.id}>{status.template?.name ?? status.id}</SelectItem>)}
                    </Field>
                    <Field component={TextareaField} name="comment" label={t_i18n('Comment')} rows={3} maxLength={COMMENT_MAX_LENGTH} disabled={disabled} helperText={`${values.comment.length} / ${COMMENT_MAX_LENGTH}`} />
                    <Field component={SwitchField} name="applyTransitionActions" label={t_i18n('Apply onExit/onEnter actions of the crossed states')} disabled={disabled} />
                    {values.applyTransitionActions && selected?.requiresShareOrganizationInput && (
                      <ObjectOrganizationField name="shareOrganizations" label={t_i18n('Organizations to share with')} multiple disabled={disabled} style={{ width: '100%' }} />
                    )}
                    {values.applyTransitionActions && selected?.requiresUnshareOrganizationInput && (
                      <ObjectOrganizationField name="unshareOrganizations" label={t_i18n('Organizations to unshare from')} multiple disabled={disabled} style={{ width: '100%' }} />
                    )}
                  </Box>
                  <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1, mt: 2 }}>
                    <Button variant="secondary" disabled={dismissDisabled} onClick={() => setOpen(false)}>{t_i18n('Cancel')}</Button>
                    <Button type="submit" disabled={disabled || loading || loadError || !isValid || !values.targetStatusId || values.comment.length > COMMENT_MAX_LENGTH}>{t_i18n('Apply')}</Button>
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
