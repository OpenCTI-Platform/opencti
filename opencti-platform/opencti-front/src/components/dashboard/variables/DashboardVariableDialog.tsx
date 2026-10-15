import { type CSSProperties, Suspense, useMemo, useRef, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import { v4 as uuid } from 'uuid';
import Button from '@common/button/Button';
import {
  Alert,
  Combobox,
  ComboboxContent,
  ComboboxControls,
  ComboboxField as FdsComboboxField,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
  Dialog,
  DialogBody,
  DialogContent,
  DialogFooter,
  DialogTitle,
  Input,
  Radio,
  RadioGroup,
  Text,
} from '@filigran/design-system';
import { useFormatter } from '../../i18n';
import SelectFieldFds, { SelectItem } from '../../fields/SelectFieldFds';
import ComboboxField from '../../ComboboxField';
import useSchema from '../../../utils/hooks/useSchema';
import useVocabularyCategory from '../../../utils/hooks/useVocabularyCategory';
import { layerInputVars } from '../../../utils/fdsLayer';
import { DASHBOARD_VARIABLE_TYPES, type DashboardVariable, type DashboardVariableType } from '../dashboard-types';
import { draftToVariable, emptyDraft, validateDraft, variableToDraft, type DashboardVariableDraft } from './dashboardVariableDraft';
import { useDashboardVariableMutations } from './useDashboardVariableMutations';
import DashboardVariableValueInput from './DashboardVariableValueInput';
import useKillChainNames from './useKillChainNames';

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

interface KillChainNameFieldProps {
  value: string;
  disabled: boolean;
  onChange: (killChainName: string) => void;
  onBlur: () => void;
}

// One of the kill chains of the platform: a name typed by hand, unknown or differently written, would match no phase.
const KillChainNameField = ({ value, disabled, onChange, onBlur }: KillChainNameFieldProps) => {
  const { t_i18n } = useFormatter();
  const names = useKillChainNames();
  // The kill chain of an edited variable is shown even when it is not (or no longer) among them.
  const options = value && names && !names.includes(value) ? [value, ...names] : names ?? [];
  const label = t_i18n('Kill chain');
  return (
    <Combobox<string>
      options={options}
      value={value || null}
      getOptionLabel={(name) => name}
      onValueChange={(next) => onChange(typeof next === 'string' ? next : '')}
      loading={names === null}
      required
      disabled={disabled}
    >
      <ComboboxLabel required>{label}</ComboboxLabel>
      <FdsComboboxField>
        <ComboboxInput name="killChainName" onBlur={onBlur} />
        <ComboboxControls>
          <ComboboxTrigger />
        </ComboboxControls>
      </FdsComboboxField>
      <ComboboxContent emptyMessage={t_i18n('No available options')} loadingMessage={t_i18n('Loading')} listAriaLabel={label} />
    </Combobox>
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
  const nameInputRef = useRef<HTMLInputElement>(null);

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
      onOpenChange={(isOpen) => {
        if (!isOpen) onClose();
      }}
    >
      <DialogContent
        size="md"
        data-testid="dashboard-variable-dialog"
        // The content is a layer-2 surface, like a drawer, but its `layer-2` class does not reach the input backgrounds:
        // re-declared on the same node, the fields get the layer-2 fill instead of the surface colour. See utils/fdsLayer.ts.
        style={layerInputVars as CSSProperties}
        // The dialog carries no description: its fields are labelled one by one.
        aria-describedby={undefined}
        // Radix focuses the first focusable element on open, which is the close button: the name is what is typed first.
        onOpenAutoFocus={(event) => {
          if (nameInputRef.current) {
            event.preventDefault();
            nameInputRef.current.focus();
          }
        }}
      >
        <DialogTitle>
          <Text as="span" variant="title-md">{isEditing ? t_i18n('Edit variable') : t_i18n('Create variable')}</Text>
        </DialogTitle>
        <Formik<DashboardVariableDraft>
          initialValues={initialValues}
          validate={(values) => validateDraft(values, existingVariables, t_i18n)}
          onSubmit={onSubmit}
        >
          {({ values, touched, setFieldValue, setFieldTouched, submitForm, isSubmitting }) => {
            // Computed here rather than read from the form state: the fields depend on it at the very render of a change.
            const errors = validateDraft(values, existingVariables, t_i18n);
            const type = values.type === '' ? undefined : values.type;
            const parameter = type ? TYPE_PARAMETER[type] : undefined;
            // The restriction and the default value wait for the type and for its parameter, which they depend on.
            const isTypeIncomplete = !type || (parameter !== undefined && !!errors[parameter]);
            // A type, or one of its parameters, changing makes the default value meaningless.
            const forgetDefaultValue = () => setFieldValue('defaultValue', '');

            return (
              <Form className="flex flex-col gap-6 min-h-0">
                {/* The negative margin keeps the focus ring (painted outside the fields) from being clipped by the scrolling body. */}
                <DialogBody style={{ margin: 'calc(var(--spacing) * -1)', padding: 'var(--spacing)' }}>
                  <div className="flex flex-col gap-4">
                    {errors.form && <Alert severity="error" title={errors.form} />}
                    <Input
                      label={t_i18n('Name')}
                      ref={nameInputRef}
                      required
                      value={values.name}
                      onChange={(event) => setFieldValue('name', event.target.value)}
                      onBlur={() => setFieldTouched('name', true)}
                      error={errors.name && (touched.name || values.name !== '') ? errors.name : undefined}
                    />
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
                    {/* Stands for the parameter of the type until it is chosen. A type without parameter shows none. */}
                    {!type && <Input label={t_i18n('Type parameter')} disabled value="" onChange={() => {}} />}
                    {parameter === 'vocabularyCategory' && (
                      <Suspense fallback={null}>
                        <VocabularyCategoryField disabled={isEditing} onChange={forgetDefaultValue} />
                      </Suspense>
                    )}
                    {parameter === 'killChainName' && (
                      <KillChainNameField
                        value={values.killChainName}
                        disabled={isEditing}
                        onChange={(killChainName) => {
                          setFieldValue('killChainName', killChainName);
                          forgetDefaultValue();
                        }}
                        onBlur={() => setFieldTouched('killChainName', true)}
                      />
                    )}
                    {parameter === 'entityTypes' && <EntityTypesField disabled={isEditing} onChange={forgetDefaultValue} />}
                    {/* A type that cannot be restricted shows no restriction. */}
                    {(!type || RESTRICTABLE_TYPES.includes(type)) && (
                      <RadioGroup
                        aria-label={t_i18n('Restriction')}
                        orientation="vertical"
                        value={values.restrictionMode}
                        onValueChange={() => {}}
                      >
                        <Radio value="none" label={t_i18n('No restriction')} disabled={isTypeIncomplete || values.restrictionMode !== 'none'} />
                        {values.restrictionMode !== 'none' && (
                          <Radio value={values.restrictionMode} label={keptRestrictionLabel} disabled />
                        )}
                      </RadioGroup>
                    )}
                    {type ? (
                      <DashboardVariableValueInput
                        // Same key as the chips: the parameters of the type change the kind of input while the dialog is open.
                        key={`${values.type}${values.entityTypes.join()}${values.vocabularyCategory}${values.killChainName}`}
                        label={t_i18n('Default value')}
                        variable={draftToVariable(values, values.id ?? 'draft')}
                        value={values.defaultValue}
                        disabled={isTypeIncomplete}
                        onChange={(defaultValue) => setFieldValue('defaultValue', defaultValue)}
                      />
                    ) : <Input label={t_i18n('Default value')} disabled value="" onChange={() => {}} />}
                  </div>
                </DialogBody>
                <DialogFooter>
                  <Button variant="secondary" onClick={onClose}>{t_i18n('Cancel')}</Button>
                  <Button
                    data-testid="variable-dialog-submit"
                    onClick={submitForm}
                    disabled={Object.keys(errors).length > 0 || isSubmitting}
                  >
                    {isEditing ? t_i18n('Update') : t_i18n('Create')}
                  </Button>
                </DialogFooter>
              </Form>
            );
          }}
        </Formik>
      </DialogContent>
    </Dialog>
  );
};

export default DashboardVariableDialog;
