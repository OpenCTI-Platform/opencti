import React, { useMemo } from 'react';
import { Field, Form, Formik, FormikHelpers } from 'formik';
import * as Yup from 'yup';
import Box from '@mui/material/Box';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import FormButtonContainer from '@common/form/FormButtonContainer';
import Filters from '@components/common/lists/Filters';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';
import SwitchField from '../../../../components/fields/SwitchField';
import SelectFieldFds, { SelectItem } from '../../../../components/fields/SelectFieldFds';
import ComboboxField from '../../../../components/ComboboxField';
import FilterIconButton from '../../../../components/FilterIconButton';
import useAuth from '../../../../utils/hooks/useAuth';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';

export type KnowledgeDecayScope = 'relationship' | 'entity';
export type KnowledgeFreshnessPolicy = 'flag' | 'lower_confidence' | 'revoke';

export interface KnowledgeDecayRuleFormValues {
  name: string;
  description: string;
  order: number;
  active: boolean;
  target_scope: KnowledgeDecayScope;
  target_types: FieldOption[];
  freshness_policy: KnowledgeFreshnessPolicy;
  stale_after_days: number;
  freshness_confidence_step: number;
}

export interface KnowledgeDecayRuleInput {
  name: string;
  description: string;
  order: number;
  active: boolean;
  target_scope: KnowledgeDecayScope;
  target_types: string[];
  freshness_policy: KnowledgeFreshnessPolicy;
  stale_after_days: number;
  freshness_confidence_step: number | null;
  decay_filters: string | null;
}

interface KnowledgeDecayRuleFormProps {
  initialValues?: Partial<KnowledgeDecayRuleFormValues>;
  initialFilters?: FilterGroup | null;
  isEdition?: boolean;
  onSubmit: (input: KnowledgeDecayRuleInput, helpers: FormikHelpers<KnowledgeDecayRuleFormValues>) => void;
  onCancel: () => void;
}

export const KNOWLEDGE_FRESHNESS_POLICY_LABELS: Record<KnowledgeFreshnessPolicy, string> = {
  flag: 'Flag as stale',
  lower_confidence: 'Lower the confidence',
  revoke: 'Revoke',
};

// Indicators keep their own score decay
const EXCLUDED_ENTITY_TYPES = ['Indicator'];

const COMMON_FILTER_KEYS = ['objectLabel', 'objectMarking', 'createdBy', 'creator_id', 'confidence', 'corroboration_count', 'assertion_source_ids', 'assertion_source_kinds'];
const RELATIONSHIP_FILTER_KEYS = [...COMMON_FILTER_KEYS, 'fromId', 'toId', 'fromTypes', 'toTypes'];

const KnowledgeDecayRuleForm = ({ initialValues, initialFilters, isEdition = false, onSubmit, onCancel }: KnowledgeDecayRuleFormProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const { schema } = useAuth();
  const [filters, filterHelpers] = useFiltersState(initialFilters ?? undefined);

  const relationshipOptions: FieldOption[] = useMemo(() => [
    ...schema.scrs.map((type) => ({ value: type.id, label: t_i18n(`relationship_${type.id}`) })),
    { value: 'stix-sighting-relationship', label: t_i18n('relationship_stix-sighting-relationship') },
  ].sort((a, b) => a.label.localeCompare(b.label)), [schema]);
  const entityOptions: FieldOption[] = useMemo(() => [...schema.sdos, ...schema.scos]
    .filter((type) => !EXCLUDED_ENTITY_TYPES.includes(type.id))
    .map((type) => ({ value: type.id, label: t_i18n(`entity_${type.id}`) }))
    .sort((a, b) => a.label.localeCompare(b.label)), [schema]);

  const validation = Yup.object().shape({
    name: Yup.string().trim().min(2, t_i18n('Name must be at least 2 characters')).required(t_i18n('This field is required')),
    order: Yup.number().integer().required(t_i18n('This field is required')),
    target_scope: Yup.string().oneOf(['relationship', 'entity']).required(t_i18n('This field is required')),
    target_types: Yup.array().when('target_scope', {
      is: 'entity',
      then: (rule) => rule.min(1, t_i18n('Select at least one entity type')),
    }),
    freshness_policy: Yup.string().oneOf(['flag', 'lower_confidence', 'revoke']).required(t_i18n('This field is required')),
    stale_after_days: Yup.number().integer().min(1, t_i18n('The value must be greater than or equal to 1')).required(t_i18n('This field is required')),
    freshness_confidence_step: Yup.number().when('freshness_policy', {
      is: 'lower_confidence',
      then: (rule) => rule.integer().min(1, t_i18n('The value must be between 1 and 100')).max(100, t_i18n('The value must be between 1 and 100')).required(t_i18n('This field is required')),
    }),
  });

  const formInitialValues: KnowledgeDecayRuleFormValues = {
    name: '',
    description: '',
    order: 1,
    active: false,
    target_scope: 'relationship',
    target_types: [],
    freshness_policy: 'flag',
    stale_after_days: 180,
    freshness_confidence_step: 10,
    ...initialValues,
  };

  const submit = (values: KnowledgeDecayRuleFormValues, helpers: FormikHelpers<KnowledgeDecayRuleFormValues>) => {
    onSubmit({
      name: values.name.trim(),
      description: values.description,
      order: parseInt(String(values.order), 10),
      active: values.active,
      target_scope: values.target_scope,
      target_types: values.target_types.map((option) => option.value),
      freshness_policy: values.freshness_policy,
      stale_after_days: parseInt(String(values.stale_after_days), 10),
      freshness_confidence_step: values.freshness_policy === 'lower_confidence' ? parseInt(String(values.freshness_confidence_step), 10) : null,
      decay_filters: serializeFilterGroupForBackend(filters) ?? null,
    }, helpers);
  };

  return (
    <Formik<KnowledgeDecayRuleFormValues>
      initialValues={formInitialValues}
      validationSchema={validation}
      onSubmit={submit}
      onReset={onCancel}
    >
      {({ submitForm, handleReset, isSubmitting, values, setFieldValue }) => {
        const searchEntityTypes = values.target_scope === 'relationship' ? ['stix-core-relationship'] : ['Stix-Core-Object'];
        return (
          <Form data-testid="knowledge-decay-rule-form">
            <Field component={TextField} name="name" label={t_i18n('Name')} fullWidth />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              fullWidth
              multiline
              rows={2}
              style={{ marginTop: 20 }}
            />
            <Field
              component={SelectFieldFds}
              name="target_scope"
              label={t_i18n('Target scope')}
              disabled={isEdition}
              fullWidth
              containerstyle={fieldSpacingContainerStyle}
              onChange={() => {
                setFieldValue('target_types', []);
                filterHelpers.handleClearAllFilters();
              }}
            >
              <SelectItem value="relationship">{t_i18n('Relationships')}</SelectItem>
              <SelectItem value="entity">{t_i18n('Entities')}</SelectItem>
            </Field>
            <Field
              component={ComboboxField}
              name="target_types"
              multiple={true}
              style={fieldSpacingContainerStyle}
              label={values.target_scope === 'relationship' ? t_i18n('Relationship types (all if empty)') : t_i18n('Entity types')}
              options={values.target_scope === 'relationship' ? relationshipOptions : entityOptions}
            />
            <Box sx={{ paddingTop: '20px', display: 'flex', alignItems: 'center', gap: theme.spacing(1), marginBottom: theme.spacing(1) }}>
              <Filters
                availableFilterKeys={values.target_scope === 'relationship' ? RELATIONSHIP_FILTER_KEYS : COMMON_FILTER_KEYS}
                helpers={filterHelpers}
                searchContext={{ entityTypes: searchEntityTypes }}
              />
            </Box>
            <FilterIconButton filters={filters} helpers={filterHelpers} searchContext={{ entityTypes: searchEntityTypes }} />
            <Field
              component={TextField}
              variant="outlined"
              name="stale_after_days"
              label={t_i18n('Stale after (days without assertion)')}
              fullWidth
              type="number"
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={SelectFieldFds}
              name="freshness_policy"
              label={t_i18n('Policy for stale knowledge')}
              fullWidth
              containerstyle={fieldSpacingContainerStyle}
            >
              {(Object.keys(KNOWLEDGE_FRESHNESS_POLICY_LABELS) as KnowledgeFreshnessPolicy[]).map((policy) => (
                <SelectItem key={policy} value={policy}>{t_i18n(KNOWLEDGE_FRESHNESS_POLICY_LABELS[policy])}</SelectItem>
              ))}
            </Field>
            {values.freshness_policy === 'lower_confidence' && (
              <Field
                component={TextField}
                variant="outlined"
                name="freshness_confidence_step"
                label={t_i18n('Confidence step')}
                fullWidth
                type="number"
                style={fieldSpacingContainerStyle}
              />
            )}
            <Field component={TextField} variant="outlined" name="order" label={t_i18n('Order')} fullWidth type="number" style={fieldSpacingContainerStyle} />
            <Field component={SwitchField} type="checkbox" name="active" label={t_i18n('Active')} containerstyle={fieldSpacingContainerStyle} />
            <FormButtonContainer>
              <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>{t_i18n('Cancel')}</Button>
              <Button onClick={submitForm} disabled={isSubmitting} data-testid="knowledge-decay-rule-submit">
                {isEdition ? t_i18n('Update') : t_i18n('Create')}
              </Button>
            </FormButtonContainer>
          </Form>
        );
      }}
    </Formik>
  );
};

export default KnowledgeDecayRuleForm;
