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
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { DASHBOARD_VARIABLE_TYPES, type DashboardVariable, type DashboardVariableType } from '../dashboard-types';
import { draftToVariable, emptyDraft, validateDraft, variableToDraft, type DashboardVariableDraft } from './dashboardVariableDraft';
import { useDashboardVariableMutations } from './useDashboardVariableMutations';
import DashboardVariableValueInput from './DashboardVariableValueInput';
import SelectionValuesInput from './ValueInputs/SelectionValuesInput';
import RestrictionFiltersField from './RestrictionFiltersField';
import useKillChainNames from './useKillChainNames';

// The types whose values can be restricted: the others have no restriction step. Only an entity variable can be
// restricted by filter.
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
// When the platform cannot list them, a free text field takes over so that the variable can still be created.
const KillChainNameField = ({ value, disabled, onChange, onBlur }: KillChainNameFieldProps) => {
  const { t_i18n } = useFormatter();
  const { names, status } = useKillChainNames();
  const label = t_i18n('Kill chain');
  if (status === 'error') {
    return (
      <Input
        label={label}
        name="killChainName"
        required
        disabled={disabled}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        onBlur={onBlur}
        helperText={t_i18n('The kill chain names could not be loaded, type the name of the kill chain')}
      />
    );
  }
  // The kill chain of an edited variable is shown even when it is not (or no longer) among them.
  const options = value && status === 'ready' && !names.includes(value) ? [value, ...names] : names;
  return (
    <Combobox<string>
      options={options}
      value={value || null}
      getOptionLabel={(name) => name}
      onValueChange={(next) => onChange(typeof next === 'string' ? next : '')}
      loading={status === 'loading'}
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
            // A type, or one of its parameters, changing makes the default value meaningless, and the selection and
            // the rule with it. They only change in creation: they are locked in edition.
            const forgetDefaultValue = () => {
              setFieldValue('defaultValue', '');
              setFieldValue('selectionValues', []);
              setFieldValue('filters', undefined);
            };
            // A type that cannot be restricted, or restricted by filter, leaves its restriction.
            const onTypeChange = (_name: string, nextType: string) => {
              forgetDefaultValue();
              const nextRestrictable = RESTRICTABLE_TYPES.includes(nextType as DashboardVariableType);
              if (!nextRestrictable || (nextType !== 'entity' && values.restrictionMode === 'filters')) {
                setFieldValue('restrictionMode', 'none');
              }
            };
            // The values of a mode left are kept in the draft, so that coming back finds them: only the current mode is sent.
            // The default value is chosen again, among the values the new mode allows.
            const onRestrictionModeChange = (mode: string) => {
              setFieldValue('restrictionMode', mode);
              setFieldValue('defaultValue', '');
              if (mode === 'filters' && !values.filters) setFieldValue('filters', emptyFilterGroup);
            };

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
                      onChange={onTypeChange}
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
                        onValueChange={onRestrictionModeChange}
                      >
                        <Radio value="none" label={t_i18n('No restriction')} disabled={isTypeIncomplete} />
                        <Radio value="selection" label={t_i18n('Manual selection')} disabled={isTypeIncomplete} />
                        {type === 'entity' && <Radio value="filters" label={t_i18n('By filter')} disabled={isTypeIncomplete} />}
                      </RadioGroup>
                    )}
                    {type && values.restrictionMode === 'selection' && (
                      <SelectionValuesInput
                        // Same key as the default value: the parameters of the type change what can be searched.
                        key={`${values.type}${values.entityTypes.join()}${values.vocabularyCategory}${values.killChainName}`}
                        variable={draftToVariable({ ...values, restrictionMode: 'none' }, values.id ?? 'draft')}
                        label={t_i18n('Values')}
                        values={values.selectionValues}
                        disabled={isTypeIncomplete}
                        error={errors.selectionValues && (touched.selectionValues || values.selectionValues.length > 0) ? errors.selectionValues : undefined}
                        onBlur={() => setFieldTouched('selectionValues', true)}
                        onChange={(selectionValues) => {
                          setFieldValue('selectionValues', selectionValues);
                          // A default value removed from the selection is no longer allowed.
                          if (!selectionValues.includes(values.defaultValue)) setFieldValue('defaultValue', '');
                        }}
                      />
                    )}
                    {type === 'entity' && values.restrictionMode === 'filters' && (
                      <RestrictionFiltersField
                        // The editor keeps its own state: other entity types start another rule.
                        key={values.entityTypes.join()}
                        entityTypes={values.entityTypes}
                        label={t_i18n('Filters')}
                        value={values.filters}
                        error={touched.filters ? errors.filters : undefined}
                        onChange={(filters) => {
                          setFieldValue('filters', filters);
                          setFieldTouched('filters', true, false);
                          // Whether the default value still matches the rule is not known without a search: it is chosen again.
                          setFieldValue('defaultValue', '');
                        }}
                      />
                    )}
                    {type ? (
                      <DashboardVariableValueInput
                        // Same key as the chips: the parameters of the type change the kind of input while the dialog is open.
                        // The restriction too: a new mode, selection or rule searches among other values.
                        key={`${values.type}${values.entityTypes.join()}${values.vocabularyCategory}${values.killChainName}${values.restrictionMode}${values.selectionValues.join()}${JSON.stringify(values.filters ?? null)}`}
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
