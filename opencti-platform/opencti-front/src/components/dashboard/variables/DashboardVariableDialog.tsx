import { Suspense, useMemo, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import { v4 as uuid } from 'uuid';
import Stack from '@mui/material/Stack';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { Alert, Input, Radio, RadioGroup } from '@filigran/design-system';
import { useFormatter } from '../../i18n';
import SelectFieldFds, { SelectItem } from '../../fields/SelectFieldFds';
import ComboboxField from '../../ComboboxField';
import useSchema from '../../../utils/hooks/useSchema';
import useVocabularyCategory from '../../../utils/hooks/useVocabularyCategory';
import { DASHBOARD_VARIABLE_TYPES, type DashboardVariable, type DashboardVariableType } from '../dashboard-types';
import { draftToVariable, emptyDraft, validateDraft, variableToDraft, type DashboardVariableDraft } from './dashboardVariableDraft';
import { useDashboardVariableMutations } from './useDashboardVariableMutations';
import DashboardVariableValueInput from './DashboardVariableValueInput';

// The types that will support a restriction of their values (PR 2b): the others have no restriction step.
const RESTRICTABLE_TYPES: readonly DashboardVariableType[] = [
  'entity', 'label', 'marking', 'user', 'group', 'status', 'killChainPhase', 'vocabulary',
];

// The field holding the parameter of a type, when it has one.
const TYPE_PARAMETER: Partial<Record<DashboardVariableType, 'vocabularyCategory' | 'killChainName' | 'entityTypes'>> = {
  vocabulary: 'vocabularyCategory',
  killChainPhase: 'killChainName',
  entity: 'entityTypes',
};

export interface DashboardVariableDialogProps {
  open: boolean;
  workspaceId: string;
  // Edition when provided, creation otherwise.
  variable?: DashboardVariable;
  // The variables of the dashboard: names must be unique among them and their number is limited.
  existingVariables: readonly DashboardVariable[];
  onClose: () => void;
}

// The parameters of the type are locked in edition (filters already reference the variable) and, in creation,
// changing one makes the default value meaningless.
interface ParameterFieldProps {
  disabled: boolean;
  onChange: () => void;
}

const VocabularyCategoryField = ({ disabled, onChange }: ParameterFieldProps) => {
  const { t_i18n } = useFormatter();
  const { categoriesOptions } = useVocabularyCategory();
  return (
    <Field
      component={SelectFieldFds}
      name="vocabularyCategory"
      label={t_i18n('Vocabulary category')}
      fullWidth
      required
      disabled={disabled}
      onChange={onChange}
    >
      {categoriesOptions.map(({ value, label }) => (
        <SelectItem key={value} value={value}>{label}</SelectItem>
      ))}
    </Field>
  );
};

const EntityTypesField = ({ disabled, onChange }: ParameterFieldProps) => {
  const { t_i18n } = useFormatter();
  const { allEntityTypes } = useSchema();
  return (
    <Field
      component={ComboboxField}
      name="entityTypes"
      label={t_i18n('Entity types')}
      options={allEntityTypes}
      getOptionLabel={(entityType: string) => t_i18n(`entity_${entityType}`)}
      multiple
      required
      disabled={disabled}
      onChange={onChange}
    />
  );
};

const DashboardVariableDialog = ({ open, workspaceId, variable, existingVariables, onClose }: DashboardVariableDialogProps) => {
  const { t_i18n } = useFormatter();
  const { upsert } = useDashboardVariableMutations(workspaceId);
  const isEditing = variable !== undefined;
  const initialValues = useMemo(() => (variable ? variableToDraft(variable) : emptyDraft), [variable]);
  // Kept for the whole life of the dialog: submitting again after a failure must not create a second variable.
  const [newId] = useState(() => uuid());

  const typeLabels: Record<DashboardVariableType, string> = {
    entity: t_i18n('Entity'),
    label: t_i18n('Label'),
    marking: t_i18n('Marking'),
    user: t_i18n('User'),
    group: t_i18n('Group'),
    status: t_i18n('Status'),
    killChainPhase: t_i18n('Kill chain phase'),
    vocabulary: t_i18n('Vocabulary'),
    entityType: t_i18n('Entity type'),
    text: t_i18n('Text'),
    numeric: t_i18n('Numeric'),
    boolean: t_i18n('Boolean'),
    date: t_i18n('Date'),
  };
  // A restriction set outside of this dialog is kept as is: its mode can neither be chosen nor left.
  const keptRestrictionLabel = variable?.restriction.mode === 'selection'
    ? t_i18n('Manual selection')
    : t_i18n('By filter');

  const onSubmit = async (values: DashboardVariableDraft) => {
    try {
      await upsert(draftToVariable(values, values.id ?? newId));
      onClose();
    } catch {
      // The mutation hook already notified the user: the dialog stays open so nothing typed is lost.
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="medium"
      title={isEditing ? t_i18n('Edit variable') : t_i18n('Create variable')}
      data-testid="dashboard-variable-dialog"
    >
      <Formik<DashboardVariableDraft>
        initialValues={initialValues}
        validate={(values) => validateDraft(values, existingVariables, t_i18n)}
        onSubmit={onSubmit}
      >
        {({ values, touched, setFieldValue, setFieldTouched, submitForm, isSubmitting }) => {
          // Computed here rather than read from the form state: the steps depend on it at the very render of a change.
          const errors = validateDraft(values, existingVariables, t_i18n);
          const type = values.type === '' ? undefined : values.type;
          const parameter = type ? TYPE_PARAMETER[type] : undefined;
          const hasNameStep = !errors.name;
          const hasParameterStep = hasNameStep && parameter !== undefined;
          const hasRestrictionStep = hasNameStep && !!type && RESTRICTABLE_TYPES.includes(type) && (!parameter || !errors[parameter]);
          const hasValueStep = hasNameStep && !!type && (!parameter || !errors[parameter]);
          // A type, or one of its parameters, changing makes the default value meaningless.
          const forgetDefaultValue = () => setFieldValue('defaultValue', '');

          return (
            <Form>
              <Stack gap={2}>
                {errors.form && <Alert severity="error" title={errors.form} />}
                <Input
                  label={t_i18n('Name')}
                  required
                  autoFocus
                  value={values.name}
                  onChange={(event) => setFieldValue('name', event.target.value)}
                  onBlur={() => setFieldTouched('name', true)}
                  error={errors.name && (touched.name || values.name !== '') ? errors.name : undefined}
                />
                {hasNameStep && (
                  <Field
                    component={SelectFieldFds}
                    name="type"
                    label={t_i18n('Type')}
                    fullWidth
                    required
                    disabled={isEditing}
                    onChange={forgetDefaultValue}
                  >
                    {DASHBOARD_VARIABLE_TYPES.map((variableType) => (
                      <SelectItem key={variableType} value={variableType}>{typeLabels[variableType]}</SelectItem>
                    ))}
                  </Field>
                )}
                {hasParameterStep && parameter === 'vocabularyCategory' && (
                  <Suspense fallback={null}>
                    <VocabularyCategoryField disabled={isEditing} onChange={forgetDefaultValue} />
                  </Suspense>
                )}
                {hasParameterStep && parameter === 'killChainName' && (
                  <Input
                    label={t_i18n('Kill chain')}
                    required
                    disabled={isEditing}
                    value={values.killChainName}
                    onChange={(event) => {
                      setFieldValue('killChainName', event.target.value);
                      forgetDefaultValue();
                    }}
                    onBlur={() => setFieldTouched('killChainName', true)}
                  />
                )}
                {hasParameterStep && parameter === 'entityTypes' && <EntityTypesField disabled={isEditing} onChange={forgetDefaultValue} />}
                {hasRestrictionStep && (
                  <RadioGroup
                    aria-label={t_i18n('Restriction')}
                    orientation="vertical"
                    value={values.restrictionMode}
                    onValueChange={() => {}}
                  >
                    <Radio value="none" label={t_i18n('No restriction')} disabled={values.restrictionMode !== 'none'} />
                    {values.restrictionMode !== 'none' && (
                      <Radio value={values.restrictionMode} label={keptRestrictionLabel} disabled />
                    )}
                  </RadioGroup>
                )}
                {hasValueStep && (
                  <DashboardVariableValueInput
                    // Same key as the chips: the parameters of the type change the kind of input while the dialog is open.
                    key={`${values.type}${values.entityTypes.join()}${values.vocabularyCategory}${values.killChainName}`}
                    label={t_i18n('Default value')}
                    variable={draftToVariable(values, values.id ?? 'draft')}
                    value={values.defaultValue}
                    onChange={(defaultValue) => setFieldValue('defaultValue', defaultValue)}
                  />
                )}
              </Stack>
              <DialogActions>
                <Button variant="secondary" onClick={onClose}>{t_i18n('Cancel')}</Button>
                <Button
                  data-testid="variable-dialog-submit"
                  onClick={submitForm}
                  disabled={Object.keys(errors).length > 0 || isSubmitting}
                >
                  {isEditing ? t_i18n('Update') : t_i18n('Create')}
                </Button>
              </DialogActions>
            </Form>
          );
        }}
      </Formik>
    </Dialog>
  );
};

export default DashboardVariableDialog;
