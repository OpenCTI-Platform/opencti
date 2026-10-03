/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Field, Form, Formik, FormikHelpers } from 'formik';
import * as Yup from 'yup';
import Typography from '@mui/material/Typography';
import FormButtonContainer from '@common/form/FormButtonContainer';
import Button from '@common/button/Button';
import PlaybookFlowFieldRunAs from '@components/data/playbooks/playbookFlow/playbookFlowFields/PlaybookFlowFieldRunAs';
import TextField from '../../../../components/TextField';
import ComboboxField from '../../../../components/ComboboxField';
import SwitchField from '../../../../components/fields/SwitchField';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { InvestigationPolicyFormConnectorsQuery } from './__generated__/InvestigationPolicyFormConnectorsQuery.graphql';
import { AUTONOMOUS_ACTION_LABELS, AUTONOMOUS_ACTIONS, type InvestigationPolicyFormPolicy, type InvestigationPolicyFormValues, type Option } from './investigationPolicyUtils';

const investigationPolicyFormConnectorsQuery = graphql`
  query InvestigationPolicyFormConnectorsQuery {
    investigationEnrichmentConnectors {
      id
      name
      active
      connector_scope
    }
  }
`;

export const investigationPolicyValidator = (t: (value: string) => string) => Yup.object().shape({
  name: Yup.string().trim().min(2, t('This field must be at least 2 characters')).required(t('This field is required')),
  pack_id: Yup.string().max(200),
  agent_slug: Yup.string().max(200),
  auto_approve_min_confidence: Yup.number().integer().min(0).max(100).required(t('This field is required')),
  attribution_min_confidence: Yup.number().integer().min(0).max(100).required(t('This field is required')),
  max_tool_calls: Yup.number().integer().min(1).max(500).required(t('This field is required')),
  max_enrichment_jobs: Yup.number().integer().min(0).max(200).required(t('This field is required')),
  max_minutes: Yup.number().integer().min(1).max(1440).required(t('This field is required')),
});

interface InvestigationPolicyFormProps {
  policy: InvestigationPolicyFormPolicy;
  submitLabel: string;
  onSubmit: (values: InvestigationPolicyFormValues, helpers: FormikHelpers<InvestigationPolicyFormValues>) => void;
  onCancel: () => void;
}

const InvestigationPolicyForm = ({ policy, submitLabel, onSubmit, onCancel }: InvestigationPolicyFormProps) => {
  const { t_i18n } = useFormatter();
  const { investigationEnrichmentConnectors } = useLazyLoadQuery<InvestigationPolicyFormConnectorsQuery>(investigationPolicyFormConnectorsQuery, {});
  const connectorOptions: Option[] = investigationEnrichmentConnectors.map((connector) => ({
    value: connector.id,
    label: connector.active ? connector.name : `${connector.name} (${t_i18n('inactive')})`,
  }));
  const actionOptions: Option[] = AUTONOMOUS_ACTIONS.map((action) => ({ value: action, label: t_i18n(AUTONOMOUS_ACTION_LABELS[action]) }));
  // A connector removed since the policy was saved still shows, by its id, so it can be unselected.
  const connectorOption = (id: string): Option => connectorOptions.find((option) => option.value === id) ?? { value: id, label: id };
  const initialValues: InvestigationPolicyFormValues = {
    name: policy.name,
    description: policy.description ?? '',
    is_default: policy.is_default,
    pack_id: policy.pack_id ?? '',
    agent_slug: policy.agent_slug ?? '',
    allowed_actions: actionOptions.filter((option) => policy.allowed_actions.includes(option.value)),
    enrichment_connector_ids: policy.enrichment_connector_ids.map(connectorOption),
    approval_connector_ids: policy.approval_connector_ids.map(connectorOption),
    auto_approve_low_risk: policy.auto_approve_low_risk,
    auto_approve_min_confidence: policy.auto_approve_min_confidence,
    attribution_min_confidence: policy.attribution_min_confidence,
    max_tool_calls: policy.max_tool_calls,
    max_enrichment_jobs: policy.max_enrichment_jobs,
    max_minutes: policy.max_minutes,
    trigger_on_case_rfi_creation: policy.trigger_on_case_rfi_creation,
    run_as: policy.runAs ? { value: policy.runAs.id, label: policy.runAs.name } : null,
  };
  return (
    <Formik<InvestigationPolicyFormValues>
      initialValues={initialValues}
      validationSchema={investigationPolicyValidator(t_i18n)}
      onSubmit={onSubmit}
    >
      {({ submitForm, isSubmitting }) => (
        <Form>
          <Field component={TextField} name="name" label={t_i18n('Name')} fullWidth required />
          <Field component={TextField} name="description" label={t_i18n('Description')} fullWidth multiline rows={2} style={{ marginTop: 20 }} />
          <Field component={SwitchField} type="checkbox" name="is_default" label={t_i18n('Default policy')} containerstyle={fieldSpacingContainerStyle} />
          <Typography variant="h4" sx={{ marginTop: 3 }}>{t_i18n('Investigation engine')}</Typography>
          <Field
            component={TextField}
            name="pack_id"
            label={t_i18n('Investigation pack')}
            helperText={t_i18n('Pack of the XTM One investigation engine used by the investigations of this policy. Leave empty for the default pack.')}
            fullWidth
            style={{ marginTop: 10 }}
          />
          <Field
            component={TextField}
            name="agent_slug"
            label={t_i18n('Pinned agent')}
            helperText={t_i18n('Leave empty to use the agent bound to the autonomous investigation intent in XTM One.')}
            fullWidth
            style={{ marginTop: 20 }}
          />
          <Typography variant="h4" sx={{ marginTop: 3 }}>{t_i18n('Autonomy')}</Typography>
          <Field
            component={ComboboxField}
            name="allowed_actions"
            multiple
            label={t_i18n('Actions allowed without asking')}
            helperText={t_i18n('Everything is written to the investigation draft; the draft itself is approved by an analyst unless the low-risk rule below applies.')}
            options={actionOptions}
            style={{ marginTop: 10 }}
          />
          <Field
            component={ComboboxField}
            name="enrichment_connector_ids"
            multiple
            label={t_i18n('Enrichment connectors')}
            helperText={t_i18n('Leave empty to allow every enrichment connector of the platform.')}
            options={connectorOptions}
            style={{ marginTop: 20 }}
          />
          <Field
            component={ComboboxField}
            name="approval_connector_ids"
            multiple
            label={t_i18n('Connectors that need an approval')}
            helperText={t_i18n('Paid or rate-limited services: each enrichment through them waits for an analyst approval.')}
            options={connectorOptions}
            style={{ marginTop: 20 }}
          />
          <Field
            component={SwitchField}
            type="checkbox"
            name="auto_approve_low_risk"
            label={t_i18n('Approve low-risk drafts automatically (notes and observed data only)')}
            containerstyle={fieldSpacingContainerStyle}
          />
          <Field component={TextField} name="auto_approve_min_confidence" type="number" label={t_i18n('Minimum confidence for the automatic approval (%)')} fullWidth style={{ marginTop: 20 }} />
          <Field component={TextField} name="attribution_min_confidence" type="number" label={t_i18n('Minimum confidence to write an attribution (%)')} fullWidth style={{ marginTop: 20 }} />
          <Typography variant="h4" sx={{ marginTop: 3 }}>{t_i18n('Budget')}</Typography>
          <Field component={TextField} name="max_tool_calls" type="number" label={t_i18n('Maximum tool calls')} fullWidth style={{ marginTop: 10 }} />
          <Field component={TextField} name="max_enrichment_jobs" type="number" label={t_i18n('Maximum enrichment jobs')} fullWidth style={{ marginTop: 20 }} />
          <Field component={TextField} name="max_minutes" type="number" label={t_i18n('Maximum duration (minutes)')} fullWidth style={{ marginTop: 20 }} />
          <Typography variant="h4" sx={{ marginTop: 3 }}>{t_i18n('Triggers and identity')}</Typography>
          <Field
            component={SwitchField}
            type="checkbox"
            name="trigger_on_case_rfi_creation"
            label={t_i18n('Investigate every new request for information')}
            containerstyle={fieldSpacingContainerStyle}
          />
          <PlaybookFlowFieldRunAs name="run_as" label="Run automatic investigations as" style={{ marginTop: 20 }} />
          <FormButtonContainer>
            <Button variant="secondary" onClick={onCancel} disabled={isSubmitting}>{t_i18n('Cancel')}</Button>
            <Button onClick={submitForm} disabled={isSubmitting} data-testid="investigation-policy-submit">{submitLabel}</Button>
          </FormButtonContainer>
        </Form>
      )}
    </Formik>
  );
};

export default InvestigationPolicyForm;
