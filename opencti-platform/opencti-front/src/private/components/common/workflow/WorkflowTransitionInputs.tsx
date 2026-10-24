import React, { ReactNode } from 'react';
import { Icon, Text } from '@filigran/design-system';
import { Field } from 'formik';
import * as Yup from 'yup';
import ObjectOrganizationField from '../form/ObjectOrganizationField';
import TextareaField from '../../../../components/TextareaField';
import { useFormatter } from '../../../../components/i18n';
import { CommentMode } from '../../settings/sub_types/workflow/utils';
import { COMMENT_MAX_LENGTH } from './WorkflowStatus.graphql';

export const WORKFLOW_TRANSITION_COMMENT_FIELD_ID = 'workflow-transition-comment';

// What a transition asks from the user who triggers it, on one entity or on many
export interface TransitionInputRequirements {
  commentMode?: string | null;
  requiresShareOrg: boolean;
  requiresUnshareOrg: boolean;
}

export interface TransitionInputValues {
  comment: string;
  shareOrganizations: Array<{ value: string; label?: string }>;
  unshareOrganizations: Array<{ value: string; label?: string }>;
}

export const EMPTY_TRANSITION_INPUT_VALUES: TransitionInputValues = { comment: '', shareOrganizations: [], unshareOrganizations: [] };

export const hasTransitionComment = (commentMode?: string | null) => commentMode === CommentMode.allowed || commentMode === CommentMode.required;

export const buildTransitionInputsSchema = (
  requirements: TransitionInputRequirements,
  canBypassMandatoryFields: boolean,
  t_i18n: (message: string) => string,
) => {
  const organizations = (required: boolean) => (required ? Yup.array().min(1, t_i18n('This field is required')) : Yup.array());
  return Yup.object({
    comment: requirements.commentMode === CommentMode.required && !canBypassMandatoryFields
      ? Yup.string().trim().required(t_i18n('This field is required')).max(COMMENT_MAX_LENGTH)
      : Yup.string().trim().max(COMMENT_MAX_LENGTH),
    shareOrganizations: organizations(requirements.requiresShareOrg),
    unshareOrganizations: organizations(requirements.requiresUnshareOrg),
  });
};

// The organizations a share/unshare action configured without any receives at runtime
export const buildTransitionRuntimeParams = (requirements: TransitionInputRequirements, values: TransitionInputValues) => {
  const runtimeParams: { shareOrganizationIds?: string[]; unshareOrganizationIds?: string[] } = {};
  if (requirements.requiresShareOrg) runtimeParams.shareOrganizationIds = values.shareOrganizations.map((organization) => organization.value);
  if (requirements.requiresUnshareOrg) runtimeParams.unshareOrganizationIds = values.unshareOrganizations.map((organization) => organization.value);
  return runtimeParams;
};

interface WorkflowTransitionInputsProps {
  requirements: TransitionInputRequirements;
  canBypassMandatoryFields: boolean;
  commentLength: number;
  disabled?: boolean;
  // Inside a dialog, the comment prompt is the dialog description
  renderCommentPrompt?: (prompt: ReactNode) => ReactNode;
}

// Comment and organization fields of a transition, inside a Formik form of TransitionInputValues
const WorkflowTransitionInputs = ({
  requirements,
  canBypassMandatoryFields,
  commentLength,
  disabled = false,
  renderCommentPrompt = (prompt) => <div className="flex flex-col gap-2">{prompt}</div>,
}: WorkflowTransitionInputsProps) => {
  const { t_i18n } = useFormatter();
  const organizationsField = (name: string, title: string) => (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <Icon name="triangle-alert" size={16} className="text-icon-warning" aria-hidden />
        <Text variant="title-sm">{title}</Text>
      </div>
      <ObjectOrganizationField
        name={name}
        label={t_i18n('Organizations')}
        multiple={true}
        disabled={disabled}
        style={{ width: '100%' }}
        alert={false}
      />
    </div>
  );
  return (
    <>
      {hasTransitionComment(requirements.commentMode) && (
        <div className="flex flex-col gap-4">
          {renderCommentPrompt(
            <>
              <Text variant="title-sm">{t_i18n('Add a comment')}</Text>
              <Text variant="content-compact">
                {requirements.commentMode === CommentMode.required
                  ? t_i18n('A comment is required before changing the status.')
                  : t_i18n('You can optionally add a comment before changing the status.')}
              </Text>
            </>,
          )}
          <Field
            component={TextareaField}
            id={WORKFLOW_TRANSITION_COMMENT_FIELD_ID}
            name="comment"
            label={t_i18n('Comment')}
            required={requirements.commentMode === CommentMode.required && !canBypassMandatoryFields}
            disabled={disabled}
            rows={3}
            maxLength={COMMENT_MAX_LENGTH}
            helperText={`${commentLength} / ${COMMENT_MAX_LENGTH}`}
          />
        </div>
      )}
      {requirements.requiresShareOrg && organizationsField('shareOrganizations', t_i18n('Share with organizations'))}
      {requirements.requiresUnshareOrg && organizationsField('unshareOrganizations', t_i18n('Unshare from organizations'))}
    </>
  );
};

export default WorkflowTransitionInputs;
