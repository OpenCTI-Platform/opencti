import React from 'react';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import { useTheme } from '@mui/styles';
import { Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import EEChip from '@components/common/entreprise_edition/EEChip';
import CreateEntityControlledDial from '../../../components/CreateEntityControlledDial';
import TextField from '../../../components/TextField';
import TextareaField from '../../../components/TextareaField';
import SwitchField from '../../../components/fields/SwitchField';
import SelectFieldFds, { SelectItem } from '../../../components/fields/SelectFieldFds';
import MarkdownField from '../../../components/fields/markdownField/MarkdownField';
import FormButtonContainer from '../../../components/common/form/FormButtonContainer';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { handleErrorInForm } from '../../../relay/environment';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useDefaultValues from '../../../utils/hooks/useDefaultValues';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../utils/hooks/useEntitySettings';
import useFiltersState from '../../../utils/filters/useFiltersState';
import { emptyFilterGroup, serializeFilterGroupForBackend } from '../../../utils/filters/filtersUtils';
import { insertNode } from '../../../utils/store';
import useMarkdownCreationFilesInput from '../../../utils/markdown/useMarkdownCreationFilesInput';
import CreatedByField from '../common/form/CreatedByField';
import ObjectLabelField from '../common/form/ObjectLabelField';
import ObjectMarkingField from '../common/form/ObjectMarkingField';
import { ExternalReferencesField } from '../common/form/ExternalReferencesField';
import StixCoreObjectsField from '../common/form/StixCoreObjectsField';
import ObservableTypesField from '../common/form/ObservableTypesField';
import { HuntCodeEditorField } from './HuntCodeEditor';
import HuntSigmaValidation from './HuntSigmaValidation';
import HuntNativeQueriesField from './HuntNativeQueriesField';
import HuntScheduleField from './HuntScheduleField';
import HuntTriggerFiltersField from './HuntTriggerFiltersField';
import { validateHuntSchedule } from './hunt-schedule-utils';
import {
  emptyHuntFormValues,
  hasHuntLogic,
  HUNT_ENTITY_TYPE,
  HUNT_MAX_ESCALATION_THRESHOLD,
  HUNT_MAX_RESULTS_PER_RUN,
  HUNT_MAX_TIME_WINDOW_HOURS,
  HUNT_SCOPE_TYPES,
  HUNT_SOURCE_TYPES,
  HUNT_TARGET_TYPES,
  HUNT_TECHNIQUE_TYPES,
  type HuntFormValues,
  normalizeNativeQueries,
  toHuntAddInput,
} from './hunt-utils';
import { PATH_HUNT } from '../common/routes/paths';
import { HuntCreationMutation, HuntCreationMutation$data } from './__generated__/HuntCreationMutation.graphql';
import { HuntsListQuery$variables } from './__generated__/HuntsListQuery.graphql';

export const huntCreationMutation = graphql`
  mutation HuntCreationMutation($input: HuntAddInput!) {
    huntAdd(input: $input) {
      id
      standard_id
      name
      entity_type
      parent_types
      representative {
        main
      }
      ...Hunts_HuntFragment
    }
  }
`;

export const SIGMA_RULE_PLACEHOLDER = `title: Encoded PowerShell command line
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: ' -enc '
  condition: selection
level: high`;

export const useHuntFormValidation = () => {
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useIsMandatoryAttribute(HUNT_ENTITY_TYPE);
  const integerBetween = (min: number, max: number) => Yup.number()
    .typeError(t_i18n('The value must be a number'))
    .integer(t_i18n('The value must be an integer'))
    .min(min, t_i18n('The value must be greater than or equal to {value}', { values: { value: min } }))
    .max(max, t_i18n('The value must be less than or equal to {value}', { values: { value: max } }));
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2, t_i18n('Name must be at least 2 characters')),
    description: Yup.string().nullable(),
    hypothesis: Yup.string().nullable(),
    hunt_type: Yup.string().oneOf(['telemetry', 'infrastructure']),
    hunt_status: Yup.string().oneOf(['draft', 'active', 'paused', 'retired'])
      .test('hunt-logic', t_i18n('An active hunt needs its logic: a Sigma rule or a native query (an internet query for infrastructure hunts)'), function testLogic(status) {
        if (status !== 'active') return true;
        const values = this.parent as HuntFormValues;
        return hasHuntLogic({ hunt_type: values.hunt_type, sigma_rule: values.sigma_rule, native_queries: normalizeNativeQueries(values.native_queries ?? []) });
      }),
    sigma_rule: Yup.string().nullable(),
    native_queries: Yup.array().of(Yup.object().shape({
      platform: Yup.string().required(t_i18n('This field is required')),
      language: Yup.string().required(t_i18n('This field is required')),
      query: Yup.string().trim().required(t_i18n('This field is required')),
      pipeline: Yup.string().nullable(),
    })),
    schedule_mode: Yup.string().oneOf(['manual', 'standing', 'cron']),
    schedule_cron: Yup.string().when('schedule_mode', {
      is: 'cron',
      then: (schema) => schema.required(t_i18n('This field is required'))
        .test('cron', t_i18n('Invalid cron expression, or more often than every 15 minutes'), (value) => validateHuntSchedule(value ?? '').valid),
      otherwise: (schema) => schema.nullable(),
    }),
    time_window_hours: integerBetween(1, HUNT_MAX_TIME_WINDOW_HOURS).required(t_i18n('This field is required')),
    escalation_threshold: integerBetween(1, HUNT_MAX_ESCALATION_THRESHOLD).required(t_i18n('This field is required')),
    hunt_max_results: Yup.mixed().test('max-results', t_i18n('The value must be an integer between 1 and {max}', { values: { max: HUNT_MAX_RESULTS_PER_RUN } }), (value) => {
      if (value === '' || value === null || value === undefined) return true;
      const numeric = Number(value);
      return Number.isInteger(numeric) && numeric >= 1 && numeric <= HUNT_MAX_RESULTS_PER_RUN;
    }),
    benign_patterns: Yup.string().nullable(),
  }, mandatoryAttributes);
  const validator = useDynamicSchemaCreationValidation(mandatoryAttributes, basicShape);
  return { validator, mandatoryAttributes };
};

interface HuntCreationFormProps {
  updater?: (store: RecordSourceSelectorProxy, key: string, response: HuntCreationMutation$data['huntAdd']) => void;
  onReset?: () => void;
  onCompleted?: (hunt: HuntCreationMutation$data['huntAdd']) => void;
  /** Values prefilled by the caller, for instance the entity a hunt is created from */
  initialValues?: Partial<HuntFormValues>;
}

const SectionTitle = ({ children }: { children: React.ReactNode }) => {
  const theme = useTheme<Theme>();
  return (
    <Text variant="title-sm" as="h3" style={{ marginTop: theme.spacing(4), marginBottom: 0 }}>
      {children}
    </Text>
  );
};

export const HuntCreationForm = ({ updater, onReset, onCompleted, initialValues: prefill }: HuntCreationFormProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { validator, mandatoryAttributes } = useHuntFormValidation();
  const triggerFiltersState = useFiltersState(emptyFilterGroup);
  const { buildCreationFilesInput, registerMarkdownImagesController } = useMarkdownCreationFilesInput();
  const [commit] = useApiMutation<HuntCreationMutation>(
    huntCreationMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Hunt')} ${t_i18n('successfully created')}` },
  );
  const initialValues = useDefaultValues<HuntFormValues>(HUNT_ENTITY_TYPE, { ...emptyHuntFormValues(), ...prefill });

  const onSubmit: FormikConfig<HuntFormValues>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    const input = {
      ...buildCreationFilesInput([]),
      ...toHuntAddInput(values, serializeFilterGroupForBackend(triggerFiltersState[0])),
    };
    commit({
      variables: { input },
      updater: (store, response) => {
        if (updater && response) {
          updater(store, 'huntAdd', (response as HuntCreationMutation$data).huntAdd);
        }
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        onCompleted?.((response as HuntCreationMutation$data).huntAdd);
      },
    });
  };

  return (
    <Formik<HuntFormValues>
      initialValues={initialValues}
      validationSchema={validator}
      validateOnChange
      validateOnBlur
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form data-testid="hunt-creation-form">
          <Field
            component={TextField}
            variant="outlined"
            name="name"
            label={t_i18n('Name')}
            required={mandatoryAttributes.includes('name')}
            fullWidth
            detectDuplicate={[HUNT_ENTITY_TYPE]}
          />
          <Field
            component={MarkdownField}
            name="hypothesis"
            label={t_i18n('Hypothesis')}
            helperText={t_i18n('A falsifiable statement the hunt proves or disproves')}
            required={mandatoryAttributes.includes('hypothesis')}
            fullWidth
            multiline
            rows="3"
            style={fieldSpacingContainerStyle}
            autoPersistOnBlur={false}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            required={mandatoryAttributes.includes('description')}
            fullWidth
            multiline
            rows="4"
            style={fieldSpacingContainerStyle}
            autoPersistOnBlur={false}
            registerMarkdownImagesController={registerMarkdownImagesController}
            uploadFileMarkings={values.objectMarking.map(({ value }) => value)}
          />
          <div style={{ ...fieldSpacingContainerStyle, display: 'flex', gap: theme.spacing(2) }}>
            <Field component={SelectFieldFds} name="hunt_type" label={t_i18n('Hunt type')} fullWidth containerstyle={{ flex: 1 }}>
              <SelectItem value="telemetry">{t_i18n('Telemetry (inside-out)')}</SelectItem>
              <SelectItem value="infrastructure">{t_i18n('Infrastructure (outside-in)')}</SelectItem>
            </Field>
            <Field component={SelectFieldFds} name="hunt_status" label={t_i18n('Status')} fullWidth containerstyle={{ flex: 1 }}>
              <SelectItem value="draft">{t_i18n('Draft')}</SelectItem>
              <SelectItem value="active">{t_i18n('Active')}</SelectItem>
            </Field>
          </div>

          <SectionTitle>{t_i18n('Logic')}</SectionTitle>
          {values.hunt_type === 'telemetry' && (
            <div style={fieldSpacingContainerStyle}>
              <Field
                component={HuntCodeEditorField}
                name="sigma_rule"
                label={t_i18n('Sigma rule')}
                language="yaml"
                placeholder={SIGMA_RULE_PLACEHOLDER}
                minRows={10}
                testId="hunt-sigma-editor"
              />
              <HuntSigmaValidation sigmaRule={values.sigma_rule} />
            </div>
          )}
          <div style={fieldSpacingContainerStyle}>
            <HuntNativeQueriesField />
          </div>

          <SectionTitle>{t_i18n('Execution')}</SectionTitle>
          {values.hunt_type === 'telemetry' && (
            <StixCoreObjectsField
              name="scopePlatforms"
              label={t_i18n('Security platforms (empty for all)')}
              types={HUNT_SCOPE_TYPES}
              multiple
              disableCreation
              style={fieldSpacingContainerStyle}
            />
          )}
          <div style={fieldSpacingContainerStyle}>
            <HuntScheduleField />
          </div>
          {values.schedule_mode === 'standing' && <HuntTriggerFiltersField filtersState={triggerFiltersState} />}
          <div style={{ ...fieldSpacingContainerStyle, display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
            <Field
              component={SwitchField}
              type="checkbox"
              name="hunt_pir_activation"
              label={t_i18n('Activate when a PIR flags one of its targets')}
              disabled={!isEnterpriseEdition}
            />
            {!isEnterpriseEdition && <EEChip feature={t_i18n('PIR activation')} />}
          </div>
          <div style={{ ...fieldSpacingContainerStyle, display: 'flex', gap: theme.spacing(2) }}>
            <div style={{ flex: 1 }}>
              <Field component={TextField} variant="outlined" type="number" name="time_window_hours" label={t_i18n('Time window (hours)')} fullWidth required />
            </div>
            <div style={{ flex: 1 }}>
              <Field component={TextField} variant="outlined" type="number" name="escalation_threshold" label={t_i18n('Escalation threshold (hits)')} fullWidth required />
            </div>
            <div style={{ flex: 1 }}>
              <Field component={TextField} variant="outlined" type="number" name="hunt_max_results" label={t_i18n('Maximum results per run')} fullWidth />
            </div>
          </div>

          <SectionTitle>{t_i18n('Expected results')}</SectionTitle>
          <ObservableTypesField
            name="expected_observables"
            label={t_i18n('Expected observables')}
            multiple
            style={fieldSpacingContainerStyle}
          />
          <div style={fieldSpacingContainerStyle}>
            <Field
              component={TextareaField}
              name="benign_patterns"
              label={t_i18n('Benign patterns (one per line)')}
              rows={3}
              helperText={t_i18n('Known legitimate activity the triage must not escalate, for example a backup service account')}
            />
          </div>

          <SectionTitle>{t_i18n('Knowledge')}</SectionTitle>
          <StixCoreObjectsField
            name="huntTargets"
            label={t_i18n('Targeted threats')}
            types={HUNT_TARGET_TYPES}
            multiple
            disableCreation
            style={fieldSpacingContainerStyle}
          />
          <StixCoreObjectsField
            name="huntTechniques"
            label={t_i18n('Covered techniques')}
            types={HUNT_TECHNIQUE_TYPES}
            multiple
            disableCreation
            style={fieldSpacingContainerStyle}
          />
          <StixCoreObjectsField
            name="huntSources"
            label={t_i18n('Based on (indicators, reports)')}
            types={HUNT_SOURCE_TYPES}
            multiple
            disableCreation
            style={fieldSpacingContainerStyle}
          />
          <CreatedByField
            name="createdBy"
            required={mandatoryAttributes.includes('createdBy')}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ObjectLabelField
            name="objectLabel"
            required={mandatoryAttributes.includes('objectLabel')}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.objectLabel}
          />
          <ObjectMarkingField
            name="objectMarking"
            required={mandatoryAttributes.includes('objectMarking')}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ExternalReferencesField
            name="externalReferences"
            required={mandatoryAttributes.includes('externalReferences')}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.externalReferences}
          />
          <FormButtonContainer>
            <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
              {t_i18n('Cancel')}
            </Button>
            <Button onClick={submitForm} disabled={isSubmitting} data-testid="hunt-creation-submit">
              {t_i18n('Create')}
            </Button>
          </FormButtonContainer>
        </Form>
      )}
    </Formik>
  );
};

const CreateHuntControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial entityType={HUNT_ENTITY_TYPE} {...props} />
);

interface HuntCreationProps {
  paginationOptions: HuntsListQuery$variables;
}

/** Creation drawer of the hunts list (manual hunts, Community Edition). */
const HuntCreation = ({ paginationOptions }: HuntCreationProps) => {
  const { t_i18n } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_hunts', paginationOptions, 'huntAdd');
  return (
    <Drawer title={t_i18n('Create a hunt')} controlledDial={CreateHuntControlledDial} size="large">
      {({ onClose }) => (
        <HuntCreationForm updater={updater} onCompleted={onClose} onReset={onClose} />
      )}
    </Drawer>
  );
};

interface HuntCreationDrawerProps {
  open: boolean;
  onClose: () => void;
  initialValues?: Partial<HuntFormValues>;
}

/** Controlled creation drawer, prefilled, opening the created hunt (used by "Hunt this"). */
export const HuntCreationDrawer = ({ open, onClose, initialValues }: HuntCreationDrawerProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  return (
    <Drawer title={t_i18n('Create a hunt')} open={open} onClose={onClose} size="large">
      <HuntCreationForm
        initialValues={initialValues}
        onReset={onClose}
        onCompleted={(hunt) => {
          onClose();
          if (hunt) {
            navigate(PATH_HUNT(hunt.id));
          }
        }}
      />
    </Drawer>
  );
};

export default HuntCreation;
