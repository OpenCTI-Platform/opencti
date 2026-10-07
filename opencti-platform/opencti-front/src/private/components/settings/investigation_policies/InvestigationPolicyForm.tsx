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
import { Field, Form, Formik, FormikHelpers, useFormikContext } from 'formik';
import * as Yup from 'yup';
import Typography from '@mui/material/Typography';
import { Select, SelectContent, SelectHelperText, SelectLabel, SelectTrigger, SelectValue } from '@filigran/design-system';
import FormButtonContainer from '@common/form/FormButtonContainer';
import Button from '@common/button/Button';
import PlaybookFlowFieldRunAs from '@components/data/playbooks/playbookFlow/playbookFlowFields/PlaybookFlowFieldRunAs';
import TextField from '../../../../components/TextField';
import ComboboxField from '../../../../components/ComboboxField';
import SwitchField from '../../../../components/fields/SwitchField';
import SelectFieldFds, { SelectItem } from '../../../../components/fields/SelectFieldFds';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { engineReasonLabel } from '../../investigation_runs/investigationRunUtils';
import { CASE_AUTOPILOT_POLICIES_DOCS_URL } from '../../investigation_runs/investigationRunOutcomes';
import { InvestigationPolicyFormQuery, InvestigationPolicyFormQuery$data } from './__generated__/InvestigationPolicyFormQuery.graphql';
import {
  AUTONOMOUS_ACTION_LABELS,
  AUTONOMOUS_ACTIONS,
  DEFAULT_PACK_VALUE,
  toPackOptions,
  type InvestigationPolicyFormPolicy,
  type InvestigationPolicyFormValues,
  type Option,
} from './investigationPolicyUtils';

const investigationPolicyFormQuery = graphql`
  query InvestigationPolicyFormQuery {
    investigationEnrichmentConnectors {
      id
      name
      active
      connector_scope
    }
    investigationPacks {
      available
      reason
      packs {
        slug
        label
        description
        recommended
        options {
          key
          label
          description
          default
          choices {
            value
            label
            description
          }
        }
      }
    }
  }
`;

type InvestigationPackItem = InvestigationPolicyFormQuery$data['investigationPacks']['packs'][number];

export const investigationPolicyValidator = (t: (value: string) => string) => Yup.object().shape({
  name: Yup.string().trim().min(2, t('This field must be at least 2 characters')).required(t('This field is required')),
  pack_id: Yup.string().max(200),
  agent_slug: Yup.string().max(200),
  auto_approve_min_confidence: Yup.number().integer().min(0).max(100).required(t('This field is required')),
  attribution_min_confidence: Yup.number().integer().min(0).max(100).required(t('This field is required')),
  max_iterations: Yup.number().integer().min(1).max(50).required(t('This field is required')),
  max_enrichment_jobs: Yup.number().integer().min(0).max(200).required(t('This field is required')),
  max_minutes: Yup.number().integer().min(1).max(1440).required(t('This field is required')),
});

/** The options of the selected pack; an option left unset runs with the pack's own default. */
const PackOptionsFields = ({ pack }: { pack: InvestigationPackItem | undefined }) => {
  const { t_i18n } = useFormatter();
  const { values, setFieldValue } = useFormikContext<InvestigationPolicyFormValues>();
  if (!pack || pack.options.length === 0) return null;
  return (
    <>
      {pack.options.map((option) => (
        <div key={option.key} style={{ marginTop: 20 }} data-testid={`investigation-pack-option-${option.key}`}>
          <Select
            value={values.pack_options[option.key] ?? option.default ?? ''}
            onValueChange={(next) => setFieldValue('pack_options', { ...values.pack_options, [option.key]: next })}
          >
            <SelectLabel>{option.label}</SelectLabel>
            <SelectTrigger className="w-full" aria-label={option.label}>
              <SelectValue placeholder={t_i18n('Pack default')} />
            </SelectTrigger>
            <SelectContent aria-label={option.label}>
              {option.choices.map((choice) => (
                <SelectItem key={choice.value} value={choice.value}>{choice.label}</SelectItem>
              ))}
            </SelectContent>
            {option.description && <SelectHelperText>{option.description}</SelectHelperText>}
          </Select>
        </div>
      ))}
    </>
  );
};

interface PackPickerProps {
  catalog: InvestigationPolicyFormQuery$data['investigationPacks'];
  storedPackId: string | null | undefined;
}

/** The pack of the XTM One investigation engine, from the packs the connected XTM One offers. */
const PackPicker = ({ catalog, storedPackId }: PackPickerProps) => {
  const { t_i18n } = useFormatter();
  const { values, setFieldValue } = useFormikContext<InvestigationPolicyFormValues>();
  const packs = catalog.packs;
  // A pack removed from XTM One since the policy was saved still shows, by its slug, so it can be changed.
  const orphanPackId = storedPackId && !packs.some((pack) => pack.slug === storedPackId) ? storedPackId : null;
  const reason = catalog.available ? null : engineReasonLabel(catalog.reason);
  const helper = reason
    ? `${t_i18n('The packs of XTM One cannot be listed')}: ${t_i18n(reason)}`
    : t_i18n('Pack of the XTM One investigation engine used by the investigations of this policy.');
  const selected = packs.find((pack) => pack.slug === values.pack_id);
  return (
    <>
      <Field
        component={SelectFieldFds}
        name="pack_id"
        label={t_i18n('Investigation pack')}
        helpertext={helper}
        fullWidth
        containerstyle={{ marginTop: 10 }}
        onChange={() => setFieldValue('pack_options', {})}
      >
        <SelectItem value={DEFAULT_PACK_VALUE}>{t_i18n('Default pack (OpenCTI case investigation)')}</SelectItem>
        {packs.map((pack) => (
          <SelectItem key={pack.slug} value={pack.slug}>
            {pack.recommended ? `${pack.label} (${t_i18n('recommended')})` : pack.label}
          </SelectItem>
        ))}
        {orphanPackId && <SelectItem value={orphanPackId}>{`${orphanPackId} (${t_i18n('not offered by XTM One')})`}</SelectItem>}
      </Field>
      {selected?.description && (
        <Typography variant="body2" color="text.secondary" sx={{ marginTop: 1 }}>{selected.description}</Typography>
      )}
      <PackOptionsFields pack={selected} />
    </>
  );
};

interface InvestigationPolicyFormProps {
  policy: InvestigationPolicyFormPolicy;
  submitLabel: string;
  onSubmit: (values: InvestigationPolicyFormValues, helpers: FormikHelpers<InvestigationPolicyFormValues>) => void;
  onCancel: () => void;
}

const InvestigationPolicyForm = ({ policy, submitLabel, onSubmit, onCancel }: InvestigationPolicyFormProps) => {
  const { t_i18n } = useFormatter();
  const { investigationEnrichmentConnectors, investigationPacks } = useLazyLoadQuery<InvestigationPolicyFormQuery>(investigationPolicyFormQuery, {});
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
    pack_id: policy.pack_id ?? DEFAULT_PACK_VALUE,
    pack_options: toPackOptions(policy.pack_options),
    agent_slug: policy.agent_slug ?? '',
    allowed_actions: actionOptions.filter((option) => policy.allowed_actions.includes(option.value)),
    enrichment_connector_ids: policy.enrichment_connector_ids.map(connectorOption),
    approval_connector_ids: policy.approval_connector_ids.map(connectorOption),
    auto_approve_low_risk: policy.auto_approve_low_risk,
    auto_approve_min_confidence: policy.auto_approve_min_confidence,
    attribution_min_confidence: policy.attribution_min_confidence,
    max_iterations: policy.max_iterations,
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
          <Typography variant="body2" sx={{ marginBottom: 2 }}>
            {t_i18n('A policy sets what Case Autopilot may do on its own, its budget and what starts it.')}
            {' '}
            <a href={CASE_AUTOPILOT_POLICIES_DOCS_URL} target="_blank" rel="noopener noreferrer">{t_i18n('Learn more')}</a>
          </Typography>
          <Field component={TextField} name="name" label={t_i18n('Name')} fullWidth required />
          <Field component={TextField} name="description" label={t_i18n('Description')} fullWidth multiline rows={2} style={{ marginTop: 20 }} />
          <Field
            component={SwitchField}
            type="checkbox"
            name="is_default"
            label={t_i18n('Default policy')}
            helpertext={t_i18n('Used by every launch and playbook that does not name another policy. Turning it on replaces the current default policy.')}
            containerstyle={fieldSpacingContainerStyle}
          />
          <Typography variant="h4" sx={{ marginTop: 3 }}>{t_i18n('Investigation engine')}</Typography>
          <PackPicker catalog={investigationPacks} storedPackId={policy.pack_id} />
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
          <Field
            component={TextField}
            name="auto_approve_min_confidence"
            type="number"
            label={t_i18n('Minimum confidence for the automatic approval (%)')}
            helperText={t_i18n('Confidence the leading hypothesis needs for a low-risk draft to be approved automatically, for example 80 (0 to 100).')}
            fullWidth
            style={{ marginTop: 20 }}
          />
          <Field
            component={TextField}
            name="attribution_min_confidence"
            type="number"
            label={t_i18n('Minimum confidence to write an attribution (%)')}
            helperText={t_i18n('Below this confidence, the leading hypothesis is reported but no attribution relationship is written to the draft, for example 70 (0 to 100).')}
            fullWidth
            style={{ marginTop: 20 }}
          />
          <Typography variant="h4" sx={{ marginTop: 3 }}>{t_i18n('Budget')}</Typography>
          <Field
            component={TextField}
            name="max_iterations"
            type="number"
            label={t_i18n('Maximum iterations')}
            helperText={t_i18n('Reasoning steps of the engine in one investigation, for example 10 (1 to 50). When they are used up, the engine ends the investigation with what it found.')}
            fullWidth
            style={{ marginTop: 10 }}
          />
          <Field
            component={TextField}
            name="max_enrichment_jobs"
            type="number"
            label={t_i18n('Maximum enrichment jobs')}
            helperText={t_i18n('Connector runs one investigation may request, for example 20 (0 to 200, 0 turns enrichment off). Further requests are then refused.')}
            fullWidth
            style={{ marginTop: 20 }}
          />
          <Field
            component={TextField}
            name="max_minutes"
            type="number"
            label={t_i18n('Maximum duration (minutes)')}
            helperText={t_i18n('Longest duration of one investigation, for example 60 (1 to 1440). Once spent, OpenCTI stops the engine run and the investigation concludes with what it found.')}
            fullWidth
            style={{ marginTop: 20 }}
          />
          <Typography variant="h4" sx={{ marginTop: 3 }}>{t_i18n('Triggers and identity')}</Typography>
          <Field
            component={SwitchField}
            type="checkbox"
            name="trigger_on_case_rfi_creation"
            label={t_i18n('Investigate every new request for information')}
            helpertext={t_i18n('Starts an investigation with this policy when a request for information is created; otherwise only on demand.')}
            containerstyle={fieldSpacingContainerStyle}
          />
          <PlaybookFlowFieldRunAs
            name="run_as"
            label="Run automatic investigations as"
            helperText={t_i18n('Automatic investigations act and read as this user, and see only what it can see. Empty: the platform administrator. Only yourself and service accounts can be selected.')}
            style={{ marginTop: 20 }}
          />
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
