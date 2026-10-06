import { graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import Button from '@common/button/Button';
import FormButtonContainer from '@common/form/FormButtonContainer';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import TextareaField from '../../../../components/TextareaField';
import ComboboxField from '../../../../components/ComboboxField';
import SwitchField from '../../../../components/fields/SwitchField';
import SelectFieldFds, { SelectItem } from '../../../../components/fields/SelectFieldFds';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { MESSAGING$ } from '../../../../relay/environment';
import useCurationLabels, { CURATION_POLICIES_DOCUMENTATION_URL, CURATION_PROPOSAL_KINDS, CURATION_SOURCE_CLASSES, notifyPayloadErrors } from '../../data/curation/curationUtils';
import { CurationPolicyFormAddMutation } from './__generated__/CurationPolicyFormAddMutation.graphql';
import { CurationPolicyFormEditMutation } from './__generated__/CurationPolicyFormEditMutation.graphql';

const policyAddMutation = graphql`
  mutation CurationPolicyFormAddMutation($input: CurationPolicyAddInput!) {
    curationPolicyAdd(input: $input) {
      id
      ...CurationPolicies_policy
    }
  }
`;

const policyEditMutation = graphql`
  mutation CurationPolicyFormEditMutation($id: ID!, $input: [EditInput!]!) {
    curationPolicyFieldPatch(id: $id, input: $input) {
      id
      ...CurationPolicies_policy
    }
  }
`;

/** Split proposals always need a human: they are never offered to a policy. */
const POLICY_KINDS = CURATION_PROPOSAL_KINDS.filter((kind) => kind !== 'split');

export interface CurationPolicyFormData {
  id: string;
  name: string;
  description?: string | null;
  policy_enabled: boolean;
  policy_entity_types: readonly string[];
  policy_kinds: readonly string[];
  policy_source_class: string;
  auto_apply_threshold: number;
  forbid_open_contradiction: boolean;
  require_adjudication: boolean;
  max_applies_per_run: number;
}

interface FormValues {
  name: string;
  description: string;
  policy_enabled: boolean;
  policy_entity_types: FieldOption[];
  policy_kinds: FieldOption[];
  policy_source_class: string;
  auto_apply_threshold: number | string;
  forbid_open_contradiction: boolean;
  require_adjudication: boolean;
  max_applies_per_run: number | string;
}

interface CurationPolicyFormProps {
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
  policy?: CurationPolicyFormData | null;
  curatedEntityTypes: readonly string[];
}

const CurationPolicyForm = ({ open, onClose, onSaved, policy, curatedEntityTypes }: CurationPolicyFormProps) => {
  const { t_i18n } = useFormatter();
  const labels = useCurationLabels();
  const [commitAdd] = useApiMutation<CurationPolicyFormAddMutation>(policyAddMutation);
  const [commitEdit] = useApiMutation<CurationPolicyFormEditMutation>(policyEditMutation);
  const typeOption = (type: string): FieldOption => ({ value: type, label: t_i18n(`entity_${type}`) });
  const kindOption = (kind: string): FieldOption => ({ value: kind, label: labels.kind(kind) });

  const validation = Yup.object().shape({
    name: Yup.string().trim().min(2, t_i18n('This field must be at least 2 characters')).required(t_i18n('This field is required')),
    policy_kinds: Yup.array().min(1, t_i18n('Select at least one proposal kind')),
    auto_apply_threshold: Yup.number()
      .typeError(t_i18n('The value must be a number'))
      .min(0.5, t_i18n('The auto-apply threshold must be between 0.5 and 1'))
      .max(1, t_i18n('The auto-apply threshold must be between 0.5 and 1'))
      .required(t_i18n('This field is required')),
    max_applies_per_run: Yup.number()
      .typeError(t_i18n('The value must be a number'))
      .integer(t_i18n('The value must be an integer'))
      .min(1, t_i18n('The maximum applies per run must be between 1 and 1000'))
      .max(1000, t_i18n('The maximum applies per run must be between 1 and 1000'))
      .required(t_i18n('This field is required')),
  });

  const initialValues: FormValues = {
    name: policy?.name ?? '',
    description: policy?.description ?? '',
    policy_enabled: policy?.policy_enabled ?? false,
    policy_entity_types: (policy?.policy_entity_types ?? []).map(typeOption),
    policy_kinds: (policy?.policy_kinds ?? ['merge', 'alias']).map(kindOption),
    policy_source_class: policy?.policy_source_class ?? 'any',
    auto_apply_threshold: policy?.auto_apply_threshold ?? 0.95,
    forbid_open_contradiction: policy?.forbid_open_contradiction ?? true,
    require_adjudication: policy?.require_adjudication ?? false,
    max_applies_per_run: policy?.max_applies_per_run ?? 100,
  };

  const toInput = (values: FormValues) => ({
    name: values.name.trim(),
    description: values.description.trim() || null,
    policy_enabled: values.policy_enabled,
    policy_entity_types: values.policy_entity_types.map((option) => option.value),
    policy_kinds: values.policy_kinds.map((option) => option.value),
    policy_source_class: values.policy_source_class,
    auto_apply_threshold: Number(values.auto_apply_threshold),
    forbid_open_contradiction: values.forbid_open_contradiction,
    require_adjudication: values.require_adjudication,
    max_applies_per_run: Number(values.max_applies_per_run),
  });

  const onSubmit = (values: FormValues, { setSubmitting, resetForm }: { setSubmitting: (flag: boolean) => void; resetForm: () => void }) => {
    const input = toInput(values);
    const done = () => {
      setSubmitting(false);
      resetForm();
      onSaved();
      onClose();
    };
    if (policy) {
      const edits = Object.entries(input).map(([key, value]) => ({
        key,
        value: Array.isArray(value) ? value : [value],
      }));
      commitEdit({
        variables: { id: policy.id, input: edits as never },
        onCompleted: (_, errors) => {
          if (notifyPayloadErrors(errors)) {
            setSubmitting(false);
            return;
          }
          MESSAGING$.notifySuccess(t_i18n('The curation policy has been updated'));
          done();
        },
        onError: () => setSubmitting(false),
      });
    } else {
      commitAdd({
        variables: { input: input as never },
        onCompleted: (_, errors) => {
          if (notifyPayloadErrors(errors)) {
            setSubmitting(false);
            return;
          }
          MESSAGING$.notifySuccess(t_i18n('The curation policy has been created'));
          done();
        },
        onError: () => setSubmitting(false),
      });
    }
  };

  return (
    <Drawer title={policy ? t_i18n('Update a curation policy') : t_i18n('Create a curation policy')} open={open} onClose={onClose}>
      <Formik<FormValues> initialValues={initialValues} validationSchema={validation} onSubmit={onSubmit} enableReinitialize>
        {({ submitForm, isSubmitting }) => (
          <Form data-testid="curation-policy-form">
            <div className="flex justify-end mb-2">
              <Button variant="tertiary" size="small" href={CURATION_POLICIES_DOCUMENTATION_URL} target="_blank" rel="noreferrer">
                {t_i18n('Learn more about curation policies')}
              </Button>
            </div>
            <Field component={TextField} variant="standard" name="name" label={t_i18n('Name')} fullWidth={true} required />
            <Field component={TextareaField} name="description" label={t_i18n('Description')} rows={2} className="mt-5" />
            <Field
              component={ComboboxField}
              name="policy_entity_types"
              multiple={true}
              label={t_i18n('Entity types (all curated types when empty)')}
              helperText={t_i18n('The policy only applies proposals whose subjects all have one of these types, for example Malware and Tool.')}
              options={curatedEntityTypes.map(typeOption)}
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={ComboboxField}
              name="policy_kinds"
              multiple={true}
              required
              label={t_i18n('Proposal kinds')}
              helperText={t_i18n('The kinds of proposals the policy applies, for example duplicates to merge. At least one.')}
              options={POLICY_KINDS.map(kindOption)}
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={SelectFieldFds}
              name="policy_source_class"
              label={t_i18n('Source class')}
              helpertext={t_i18n('Where the subjects come from: any source, connectors only, or manual edits only. Any source by default.')}
              fullWidth={true}
              containerstyle={fieldSpacingContainerStyle}
            >
              {CURATION_SOURCE_CLASSES.map((sourceClass) => (
                <SelectItem key={sourceClass} value={sourceClass}>{labels.sourceClass(sourceClass)}</SelectItem>
              ))}
            </Field>
            <Field
              component={TextField}
              variant="standard"
              type="number"
              name="auto_apply_threshold"
              label={t_i18n('Auto-apply threshold (0.5 to 1)')}
              helperText={t_i18n('The minimum confidence of a proposal the policy applies, for example 0.9. Higher: fewer, surer applies.')}
              inputProps={{ min: 0.5, max: 1, step: 0.01 }}
              fullWidth={true}
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={TextField}
              variant="standard"
              type="number"
              name="max_applies_per_run"
              label={t_i18n('Maximum applies per run')}
              helperText={t_i18n('The most proposals one run applies, from 1 to 1,000 (100 by default). The others wait for the next run, 15 minutes later.')}
              inputProps={{ min: 1, max: 1000, step: 1 }}
              fullWidth={true}
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="forbid_open_contradiction"
              label={t_i18n('Never apply when a subject has an open contradiction')}
              helpertext={t_i18n('Leaves to an analyst a proposal whose subjects carry an open contradiction proposal. On by default.')}
              containerstyle={fieldSpacingContainerStyle}
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="require_adjudication"
              label={t_i18n('Require the agreement of the OpenCTI Curator')}
              helpertext={t_i18n('Only applies a duplicate proposal the OpenCTI Curator agreed with when OpenCTI asked it. Off by default.')}
              containerstyle={{ marginTop: 10 }}
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="policy_enabled"
              label={t_i18n('Enabled')}
              helpertext={t_i18n('An enabled policy runs every 15 minutes. Run a dry run before enabling it.')}
              containerstyle={{ marginTop: 10 }}
            />
            <FormButtonContainer>
              <Button variant="secondary" onClick={onClose} disabled={isSubmitting}>
                {t_i18n('Cancel')}
              </Button>
              <Button onClick={submitForm} disabled={isSubmitting}>
                {policy ? t_i18n('Update') : t_i18n('Create')}
              </Button>
            </FormButtonContainer>
          </Form>
        )}
      </Formik>
    </Drawer>
  );
};

export default CurationPolicyForm;
