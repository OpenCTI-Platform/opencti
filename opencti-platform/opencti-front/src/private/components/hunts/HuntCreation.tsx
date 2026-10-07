import React from 'react';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import { useTheme } from '@mui/styles';
import Button from '@common/button/Button';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import CreateEntityControlledDial from '../../../components/CreateEntityControlledDial';
import TextField from '../../../components/TextField';
import SwitchField from '../../../components/fields/SwitchField';
import SelectFieldFds, { SelectItem } from '../../../components/fields/SelectFieldFds';
import MarkdownField from '../../../components/fields/markdownField/MarkdownField';
import FormButtonContainer from '../../../components/common/form/FormButtonContainer';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { handleErrorInForm, MESSAGING$ } from '../../../relay/environment';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { notifyPayloadErrors } from './hunt-mutation-utils';
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
import HuntEntitiesField from './HuntEntitiesField';
import HuntFormSectionTitle from './HuntFormSectionTitle';
import HuntRunProducesSection from './HuntRunProducesSection';
import HuntSigmaRuleField from './HuntSigmaRuleField';
import HuntBenignPatternsField from './HuntBenignPatternsField';
import { HuntAIAction, HuntAIAssistProvider, HuntPlanWithAIAction } from './HuntAIAssist';
import HuntEELabel from './HuntEELabel';
import HuntNativeQueriesField from './HuntNativeQueriesField';
import HuntScheduleField from './HuntScheduleField';
import HuntTriggerFiltersField from './HuntTriggerFiltersField';
import { validateHuntSchedule } from './hunt-schedule-utils';
import useHuntConfiguration from './useHuntConfiguration';
import HuntIocFields from './HuntIocFields';
import HuntIndicatorSupportWarning from './HuntIndicatorSupportWarning';
import { parseIocText } from './hunt-ioc-utils';
import {
  emptyHuntFormValues,
  hasHuntLogic,
  HUNT_DEFAULT_MAX_RESULTS,
  HUNT_DOCS,
  HUNT_ENTITY_TYPE,
  type HuntDerived,
  HUNT_MAX_ESCALATION_THRESHOLD,
  HUNT_SCOPE_TYPES,
  HUNT_SOURCE_TYPES,
  HUNT_TARGET_TYPES,
  HUNT_TECHNIQUE_TYPES,
  type HuntFormValues,
  normalizeNativeQueries,
  toHuntAddInput,
} from './hunt-utils';
import { HuntHelp } from './HuntLearnMore';
import HuntTypeField from './HuntTypeField';
import { HuntDerivedPanel, HuntFromEntitySummary } from './HuntFromEntity';
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
  const { minScheduleIntervalMinutes: minScheduleInterval, maxTimeWindowHours, maxResultsPerRun } = useHuntConfiguration();
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
    hunt_type: Yup.string().oneOf(['telemetry', 'indicators', 'infrastructure']),
    hunt_status: Yup.string().oneOf(['draft', 'active', 'paused', 'retired'])
      .test('hunt-logic', function testLogic(status) {
        if (status !== 'active') return true;
        const values = this.parent as HuntFormValues;
        const hasLogic = hasHuntLogic({
          hunt_type: values.hunt_type,
          sigma_rule: values.sigma_rule,
          native_queries: normalizeNativeQueries(values.native_queries ?? []),
          huntSources: [...(values.iocElements ?? []), ...(values.iocEntities ?? []), ...(values.huntSources ?? [])],
          hunt_ioc_values: parseIocText(values.ioc_values_text ?? '').values,
        });
        if (hasLogic) return true;
        let sentence = 'Add a Sigma rule or a native query';
        if (values.hunt_type === 'indicators') sentence = 'Add the indicators or observables to look for';
        if (values.hunt_type === 'infrastructure') sentence = 'Add a native query for the internet platform';
        return this.createError({ message: t_i18n('An active hunt cannot run: {sentence}', { values: { sentence: t_i18n(sentence) } }) });
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
        .test(
          'cron',
          t_i18n('Invalid cron expression, or more often than every {count} minutes', { values: { count: minScheduleInterval } }),
          (value) => validateHuntSchedule(value ?? '', minScheduleInterval).valid,
        ),
      otherwise: (schema) => schema.nullable(),
    }),
    time_window_hours: integerBetween(1, maxTimeWindowHours).required(t_i18n('This field is required')),
    escalation_threshold: integerBetween(1, HUNT_MAX_ESCALATION_THRESHOLD).required(t_i18n('This field is required')),
    hunt_max_results: Yup.mixed().test('max-results', t_i18n('The value must be an integer between 1 and {max}', { values: { max: maxResultsPerRun } }), (value) => {
      if (value === '' || value === null || value === undefined) return true;
      const numeric = Number(value);
      return Number.isInteger(numeric) && numeric >= 1 && numeric <= maxResultsPerRun;
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
  /** What "Hunt this" derived from the entity the hunt is created from */
  derived?: HuntDerived | null;
  /** Why the prefilled targeted threats are a selection, for instance the threats of a PIR with the highest score */
  targetsHelperText?: string;
}

export const HuntCreationForm = ({ updater, onReset, onCompleted, initialValues: prefill, derived, targetsHelperText }: HuntCreationFormProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { validator, mandatoryAttributes } = useHuntFormValidation();
  const triggerFiltersState = useFiltersState(emptyFilterGroup);
  const iocFiltersState = useFiltersState(emptyFilterGroup);
  const { buildCreationFilesInput, registerMarkdownImagesController } = useMarkdownCreationFilesInput();
  const [commit] = useApiMutation<HuntCreationMutation>(huntCreationMutation);
  const initialValues = useDefaultValues<HuntFormValues>(HUNT_ENTITY_TYPE, { ...emptyHuntFormValues(), ...prefill });

  const onSubmit: FormikConfig<HuntFormValues>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    const input = {
      ...buildCreationFilesInput([]),
      ...toHuntAddInput(values, serializeFilterGroupForBackend(triggerFiltersState[0]), serializeFilterGroupForBackend(iocFiltersState[0])),
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
      onCompleted: (response, errors) => {
        setSubmitting(false);
        if (notifyPayloadErrors(errors)) {
          return;
        }
        MESSAGING$.notifySuccess(`${t_i18n('entity_Hunt')} ${t_i18n('successfully created')}`);
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
          <HuntAIAssistProvider reasonInHeader>
            {derived && (
              <>
                <HuntFromEntitySummary derived={derived} style={{ marginBottom: theme.spacing(2) }} />
                <HuntDerivedPanel derived={derived} style={{ marginBottom: theme.spacing(2) }} />
              </>
            )}
            <Field
              component={TextField}
              variant="outlined"
              name="name"
              label={t_i18n('Name')}
              required={mandatoryAttributes.includes('name')}
              fullWidth
              detectDuplicate={[HUNT_ENTITY_TYPE]}
            />
            <HuntTypeField style={fieldSpacingContainerStyle} action={<HuntPlanWithAIAction />} />
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
              labelAction={<HuntAIAction request={{ kind: 'hypothesis' }} testId="hunt-hypothesis-generate" />}
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
              labelAction={<HuntAIAction request={{ kind: 'description' }} testId="hunt-description-generate" />}
            />
            <div style={fieldSpacingContainerStyle}>
              <Field
                component={SelectFieldFds}
                name="hunt_status"
                label={t_i18n('Status')}
                fullWidth
                helpertext={values.hunt_status === 'active'
                  ? t_i18n('Active: the hunt runs on its schedule or with Run now as soon as it is created')
                  : t_i18n('Draft: the hunt is saved without running, activate it from its page')}
              >
                <SelectItem value="draft">{t_i18n('Draft')}</SelectItem>
                <SelectItem value="active">{t_i18n('Active')}</SelectItem>
              </Field>
            </div>

            <HuntFormSectionTitle>{values.hunt_type === 'indicators' ? t_i18n('What to look for') : t_i18n('Logic')}</HuntFormSectionTitle>
            {values.hunt_type === 'indicators' && <HuntIocFields filtersState={iocFiltersState} />}
            {values.hunt_type === 'telemetry' && (
              <div style={fieldSpacingContainerStyle}>
                <HuntSigmaRuleField
                  label={t_i18n('Sigma rule')}
                  helperText={t_i18n('The detection logic in Sigma (YAML), translated for each platform by its hunt connector. Left empty, the hunt needs a native query.')}
                  placeholder={SIGMA_RULE_PLACEHOLDER}
                  minRows={10}
                  testId="hunt-sigma-editor"
                />
              </div>
            )}
            {values.hunt_type !== 'indicators' && (
              <div style={fieldSpacingContainerStyle}>
                <HuntNativeQueriesField label={t_i18n('Native queries')} />
              </div>
            )}

            <HuntFormSectionTitle>{t_i18n('Execution')}</HuntFormSectionTitle>
            {values.hunt_type !== 'infrastructure' && (
              <HuntEntitiesField
                name="scopePlatforms"
                label={t_i18n('Security platforms (empty for all)')}
                types={HUNT_SCOPE_TYPES}
                helpertext={t_i18n('Where the hunt runs: its hunt connectors execute it on these platforms. Left empty, every hunt-capable platform.')}
                style={fieldSpacingContainerStyle}
              />
            )}
            {values.hunt_type === 'indicators' && (
              <HuntIndicatorSupportWarning scopePlatformIds={values.scopePlatforms.map((platform) => platform.value)} style={fieldSpacingContainerStyle} />
            )}
            <div style={fieldSpacingContainerStyle}>
              <HuntScheduleField />
            </div>
            {values.schedule_mode === 'standing' && <HuntTriggerFiltersField filtersState={triggerFiltersState} />}
            <div style={fieldSpacingContainerStyle}>
              <Field
                component={SwitchField}
                type="checkbox"
                name="hunt_pir_activation"
                label={<HuntEELabel label={t_i18n('Activate when a PIR flags one of its targets')} feature={t_i18n('PIR activation')} />}
                helpertext={<HuntHelp text={t_i18n('The hunt runs when a PIR flags one of its targeted threats. Off, a PIR does not trigger it.')} href={HUNT_DOCS.pir} />}
                disabled={!isEnterpriseEdition}
              />
            </div>
            <div style={{ ...fieldSpacingContainerStyle, display: 'flex', gap: theme.spacing(2) }}>
              <div style={{ flex: 1 }}>
                <Field
                  component={TextField}
                  variant="outlined"
                  type="number"
                  name="time_window_hours"
                  label={values.hunt_type === 'indicators' ? t_i18n('Look back (hours)') : t_i18n('Time window (hours)')}
                  helperText={<HuntHelp text={t_i18n('The period of telemetry each run searches, ending when it starts, for example 168 for 7 days')} href={HUNT_DOCS.runHunt} />}
                  fullWidth
                  required
                />
              </div>
              <div style={{ flex: 1 }}>
                <Field
                  component={TextField}
                  variant="outlined"
                  type="number"
                  name="escalation_threshold"
                  label={t_i18n('Escalation threshold (hits)')}
                  helperText={<HuntHelp text={t_i18n('From this number of hits, a run proposes an incident, for example 10')} href={HUNT_DOCS.runs} />}
                  fullWidth
                  required
                />
              </div>
              <div style={{ flex: 1 }}>
                <Field
                  component={TextField}
                  variant="outlined"
                  type="number"
                  name="hunt_max_results"
                  label={t_i18n('Maximum results per run')}
                  helperText={<HuntHelp text={t_i18n('Results a run reads at most. Left empty, {count}.', { values: { count: String(HUNT_DEFAULT_MAX_RESULTS) } })} href={HUNT_DOCS.runs} />}
                  fullWidth
                />
              </div>
            </div>
            <div style={fieldSpacingContainerStyle}>
              <Field
                component={SwitchField}
                type="checkbox"
                name="escalate_manual_runs"
                label={t_i18n('Escalate the runs started by hand')}
                helpertext={<HuntHelp text={t_i18n('On, a run started by hand proposes an incident from the escalation threshold. Off, the incident is offered with a true positive verdict.')} href={HUNT_DOCS.runs} />}
              />
            </div>

            <HuntRunProducesSection huntType={values.hunt_type} />
            <HuntBenignPatternsField style={fieldSpacingContainerStyle} />

            <HuntFormSectionTitle>{t_i18n('Knowledge')}</HuntFormSectionTitle>
            <HuntEntitiesField
              name="huntTargets"
              label={t_i18n('Targeted threats')}
              types={HUNT_TARGET_TYPES}
              helpertext={targetsHelperText}
              style={fieldSpacingContainerStyle}
            />
            <HuntEntitiesField
              name="huntTechniques"
              label={t_i18n('Covered techniques')}
              types={HUNT_TECHNIQUE_TYPES}
              style={fieldSpacingContainerStyle}
            />
            {/* An indicator hunt also looks for its sources, so prefilled ones stay visible and removable */}
            {(values.hunt_type !== 'indicators' || values.huntSources.length > 0) && (
              <HuntEntitiesField
                name="huntSources"
                label={t_i18n('Based on (indicators, reports)')}
                types={HUNT_SOURCE_TYPES}
                style={fieldSpacingContainerStyle}
              />
            )}
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
          </HuntAIAssistProvider>
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

/** Inserts a created hunt in the hunts list loaded with these pagination options. */
export const insertCreatedHunt = (paginationOptions: HuntsListQuery$variables) => (store: RecordSourceSelectorProxy) => {
  insertNode(store, 'Pagination_hunts', paginationOptions, 'huntAdd');
};

/** Creation drawer of the hunts list (manual hunts, Community Edition). */
const HuntCreation = ({ paginationOptions }: HuntCreationProps) => {
  const { t_i18n } = useFormatter();
  const updater = insertCreatedHunt(paginationOptions);
  return (
    <Drawer title={t_i18n('Create a hunt')} controlledDial={CreateHuntControlledDial} size="large" learnMore={{ href: HUNT_DOCS.createHunt, testId: 'hunt-creation-learn-more' }}>
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
  /** What "Hunt this" derived from the entity the hunt is created from */
  derived?: HuntDerived | null;
  /** Why the prefilled targeted threats are a selection, for instance the threats of a PIR with the highest score */
  targetsHelperText?: string;
  /** Store update of the created hunt (for example, its insertion in the hunts list) */
  updater?: (store: RecordSourceSelectorProxy) => void;
  /** Called with the created hunt instead of opening it */
  onCreated?: () => void;
}

/** Controlled creation drawer, prefilled, opening the created hunt (used by "Hunt this" and the first use of the Hunts area). */
export const HuntCreationDrawer = ({ open, onClose, initialValues, derived, targetsHelperText, updater, onCreated }: HuntCreationDrawerProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  return (
    <Drawer title={derived ? t_i18n('Hunt {name}', { values: { name: derived.entity.name } }) : t_i18n('Create a hunt')} open={open} onClose={onClose} size="large" learnMore={{ href: HUNT_DOCS.createHunt, testId: 'hunt-creation-learn-more' }}>
      <HuntCreationForm
        initialValues={initialValues}
        derived={derived}
        targetsHelperText={targetsHelperText}
        updater={updater}
        onReset={onClose}
        onCompleted={(hunt) => {
          onClose();
          if (onCreated) {
            onCreated();
          } else if (hunt) {
            navigate(PATH_HUNT(hunt.id));
          }
        }}
      />
    </Drawer>
  );
};

export default HuntCreation;
