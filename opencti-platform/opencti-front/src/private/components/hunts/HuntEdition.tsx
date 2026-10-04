import React, { Suspense } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { useTheme } from '@mui/styles';
import Button from '@common/button/Button';
import Drawer, { DrawerControlledDialType } from '@components/common/drawer/Drawer';
import EEChip from '@components/common/entreprise_edition/EEChip';
import EditEntityControlledDial from '../../../components/EditEntityControlledDial';
import FormButtonContainer from '../../../components/common/form/FormButtonContainer';
import Loader, { LoaderVariant } from '../../../components/Loader';
import TextField from '../../../components/TextField';
import TextareaField from '../../../components/TextareaField';
import SwitchField from '../../../components/fields/SwitchField';
import SelectFieldFds, { SelectItem } from '../../../components/fields/SelectFieldFds';
import MarkdownField from '../../../components/fields/markdownField/MarkdownField';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { handleErrorInForm, MESSAGING$ } from '../../../relay/environment';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import { convertCreatedBy, convertMarkings } from '../../../utils/edition';
import { deserializeFilterGroupForFrontend, emptyFilterGroup, serializeFilterGroupForBackend } from '../../../utils/filters/filtersUtils';
import useFiltersState from '../../../utils/filters/useFiltersState';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { notifyPayloadErrors } from './hunt-mutation-utils';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { useIsMandatoryAttribute } from '../../../utils/hooks/useEntitySettings';
import CreatedByField from '../common/form/CreatedByField';
import ObjectMarkingField from '../common/form/ObjectMarkingField';
import StixCoreObjectsField from '../common/form/StixCoreObjectsField';
import ObservableTypesField from '../common/form/ObservableTypesField';
import HuntScheduleField from './HuntScheduleField';
import HuntTriggerFiltersField from './HuntTriggerFiltersField';
import { validateHuntSchedule } from './hunt-schedule-utils';
import useHuntMinScheduleInterval from './useHuntMinScheduleInterval';
import {
  buildHuntEditPatch,
  emptyHuntFormValues,
  HUNT_ENTITY_TYPE,
  HUNT_MAX_ESCALATION_THRESHOLD,
  HUNT_MAX_RESULTS_PER_RUN,
  HUNT_MAX_TIME_WINDOW_HOURS,
  HUNT_SCOPE_TYPES,
  HUNT_SOURCE_TYPES,
  HUNT_TARGET_TYPES,
  HUNT_TECHNIQUE_TYPES,
  huntScheduleFormValues,
  type HuntFormValues,
  type HuntTypeValue,
} from './hunt-utils';
import { HuntEdition_hunt$data, HuntEdition_hunt$key } from './__generated__/HuntEdition_hunt.graphql';
import { HuntEditionQuery } from './__generated__/HuntEditionQuery.graphql';
import { HuntEditionFieldPatchMutation } from './__generated__/HuntEditionFieldPatchMutation.graphql';
import { HuntEditionFocusMutation } from './__generated__/HuntEditionFocusMutation.graphql';

const huntEditionFragment = graphql`
  fragment HuntEdition_hunt on Hunt {
    id
    name
    description
    hypothesis
    hunt_type
    hunt_status
    hunt_schedule
    hunt_scope
    scopePlatforms {
      id
      name
      entity_type
    }
    trigger_filters
    hunt_pir_activation
    time_window_hours
    escalation_threshold
    hunt_max_results
    expected_observables
    benign_patterns
    huntTargets {
      id
      entity_type
      representative {
        main
      }
    }
    huntTechniques {
      id
      entity_type
      name
      x_mitre_id
    }
    huntSources {
      id
      entity_type
      representative {
        main
      }
    }
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
  }
`;

export const huntEditionQuery = graphql`
  query HuntEditionQuery($id: String!) {
    hunt(id: $id) {
      id
      ...HuntEdition_hunt
      editContext {
        name
        focusOn
      }
    }
  }
`;

const huntEditionFieldPatchMutation = graphql`
  mutation HuntEditionFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    huntFieldPatch(id: $id, input: $input) {
      id
      ...HuntEdition_hunt
      ...Hunt_hunt
      ...HuntLogic_hunt
      ...Hunts_HuntFragment
    }
  }
`;

export const huntEditionFocusMutation = graphql`
  mutation HuntEditionFocusMutation($id: ID!, $input: EditContext!) {
    huntContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const toFormValues = (hunt: HuntEdition_hunt$data): HuntFormValues => ({
  ...emptyHuntFormValues(),
  name: hunt.name,
  description: hunt.description ?? '',
  hypothesis: hunt.hypothesis ?? '',
  hunt_type: hunt.hunt_type as HuntTypeValue,
  hunt_status: hunt.hunt_status as HuntFormValues['hunt_status'],
  scopePlatforms: (hunt.scopePlatforms ?? []).map((platform) => ({ value: platform.id, label: platform.name, type: platform.entity_type })),
  ...huntScheduleFormValues(hunt.hunt_schedule),
  hunt_pir_activation: hunt.hunt_pir_activation === true,
  time_window_hours: hunt.time_window_hours,
  escalation_threshold: hunt.escalation_threshold,
  hunt_max_results: hunt.hunt_max_results ?? '',
  expected_observables: [...(hunt.expected_observables ?? [])],
  benign_patterns: (hunt.benign_patterns ?? []).join('\n'),
  huntTargets: (hunt.huntTargets ?? []).map((target) => ({ value: target.id, label: target.representative.main, type: target.entity_type })),
  huntTechniques: (hunt.huntTechniques ?? []).map((technique) => ({
    value: technique.id,
    label: technique.x_mitre_id ? `[${technique.x_mitre_id}] ${technique.name}` : technique.name,
    type: technique.entity_type,
  })),
  huntSources: (hunt.huntSources ?? []).map((source) => ({ value: source.id, label: source.representative.main, type: source.entity_type })),
  createdBy: convertCreatedBy(hunt) as HuntFormValues['createdBy'],
  objectMarking: convertMarkings(hunt) as HuntFormValues['objectMarking'],
});

interface HuntEditionFormProps {
  data: HuntEdition_hunt$key;
  onClose: () => void;
}

const HuntEditionForm = ({ data, onClose }: HuntEditionFormProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const minScheduleInterval = useHuntMinScheduleInterval();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { mandatoryAttributes } = useIsMandatoryAttribute(HUNT_ENTITY_TYPE);
  const hunt = useFragment(huntEditionFragment, data);
  const initialTriggerFilters = hunt.trigger_filters ?? '';
  const triggerFiltersState = useFiltersState(deserializeFilterGroupForFrontend(initialTriggerFilters) ?? emptyFilterGroup);
  const [commit] = useApiMutation<HuntEditionFieldPatchMutation>(huntEditionFieldPatchMutation);
  const initialValues = toFormValues(hunt);
  const integerBetween = (min: number, max: number) => Yup.number()
    .typeError(t_i18n('The value must be a number'))
    .integer(t_i18n('The value must be an integer'))
    .min(min, t_i18n('The value must be greater than or equal to {value}', { values: { value: min } }))
    .max(max, t_i18n('The value must be less than or equal to {value}', { values: { value: max } }));
  const validation = Yup.object().shape({
    name: Yup.string().trim().min(2, t_i18n('Name must be at least 2 characters')).required(t_i18n('This field is required')),
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
    time_window_hours: integerBetween(1, HUNT_MAX_TIME_WINDOW_HOURS).required(t_i18n('This field is required')),
    escalation_threshold: integerBetween(1, HUNT_MAX_ESCALATION_THRESHOLD).required(t_i18n('This field is required')),
    hunt_max_results: Yup.mixed().test('max-results', t_i18n('The value must be an integer between 1 and {max}', { values: { max: HUNT_MAX_RESULTS_PER_RUN } }), (value) => {
      if (value === '' || value === null || value === undefined) return true;
      const numeric = Number(value);
      return Number.isInteger(numeric) && numeric >= 1 && numeric <= HUNT_MAX_RESULTS_PER_RUN;
    }),
  });

  const onSubmit = (
    values: HuntFormValues,
    { setSubmitting, setErrors }: { setSubmitting: (submitting: boolean) => void; setErrors: (errors: Record<string, string>) => void },
  ) => {
    const triggerFilters = serializeFilterGroupForBackend(triggerFiltersState[0]);
    const input = buildHuntEditPatch(initialValues, initialTriggerFilters, values, triggerFilters);
    if (input.length === 0) {
      setSubmitting(false);
      onClose();
      return;
    }
    commit({
      variables: { id: hunt.id, input },
      onCompleted: (_, errors) => {
        setSubmitting(false);
        if (notifyPayloadErrors(errors)) {
          return;
        }
        MESSAGING$.notifySuccess(t_i18n('The hunt has been updated'));
        onClose();
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  return (
    <Formik<HuntFormValues> initialValues={initialValues} validationSchema={validation} onSubmit={onSubmit}>
      {({ submitForm, isSubmitting, setFieldValue, values }) => (
        <Form data-testid="hunt-edition-form">
          <Field component={TextField} variant="outlined" name="name" label={t_i18n('Name')} required fullWidth />
          <Field
            component={MarkdownField}
            name="hypothesis"
            label={t_i18n('Hypothesis')}
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
          />
          <div style={fieldSpacingContainerStyle}>
            <Field component={SelectFieldFds} name="hunt_type" label={t_i18n('Hunt type')} fullWidth>
              <SelectItem value="telemetry">{t_i18n('Telemetry (inside-out)')}</SelectItem>
              <SelectItem value="infrastructure">{t_i18n('Infrastructure (outside-in)')}</SelectItem>
            </Field>
          </div>
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
          <ObservableTypesField name="expected_observables" label={t_i18n('Expected observables')} multiple style={fieldSpacingContainerStyle} />
          <div style={fieldSpacingContainerStyle}>
            <Field component={TextareaField} name="benign_patterns" label={t_i18n('Benign patterns (one per line)')} rows={3} />
          </div>
          <StixCoreObjectsField name="huntTargets" label={t_i18n('Targeted threats')} types={HUNT_TARGET_TYPES} multiple disableCreation style={fieldSpacingContainerStyle} />
          <StixCoreObjectsField name="huntTechniques" label={t_i18n('Covered techniques')} types={HUNT_TECHNIQUE_TYPES} multiple disableCreation style={fieldSpacingContainerStyle} />
          <StixCoreObjectsField name="huntSources" label={t_i18n('Based on (indicators, reports)')} types={HUNT_SOURCE_TYPES} multiple disableCreation style={fieldSpacingContainerStyle} />
          <CreatedByField name="createdBy" required={mandatoryAttributes.includes('createdBy')} style={fieldSpacingContainerStyle} setFieldValue={setFieldValue} />
          <ObjectMarkingField name="objectMarking" required={mandatoryAttributes.includes('objectMarking')} style={fieldSpacingContainerStyle} setFieldValue={setFieldValue} />
          <FormButtonContainer>
            <Button variant="secondary" onClick={onClose} disabled={isSubmitting}>
              {t_i18n('Cancel')}
            </Button>
            <Button onClick={submitForm} disabled={isSubmitting} data-testid="hunt-edition-submit">
              {t_i18n('Update')}
            </Button>
          </FormButtonContainer>
        </Form>
      )}
    </Formik>
  );
};

interface HuntEditionContainerProps {
  queryRef: PreloadedQuery<HuntEditionQuery>;
  onClose: () => void;
  controlledDial?: DrawerControlledDialType;
}

const HuntEditionContainer = ({ queryRef, onClose, controlledDial }: HuntEditionContainerProps) => {
  const { t_i18n } = useFormatter();
  const { hunt } = usePreloadedQuery(huntEditionQuery, queryRef);
  if (!hunt) {
    return null;
  }
  return (
    <Drawer title={t_i18n('Update a hunt')} context={hunt.editContext} onClose={onClose} controlledDial={controlledDial} size="large">
      {({ onClose: closeDrawer }) => (
        <HuntEditionForm
          data={hunt}
          onClose={() => {
            closeDrawer();
            onClose();
          }}
        />
      )}
    </Drawer>
  );
};

const HuntEdition = ({ huntId }: { huntId: string }) => {
  const [commitFocus] = useApiMutation<HuntEditionFocusMutation>(huntEditionFocusMutation);
  const queryRef = useQueryLoading<HuntEditionQuery>(huntEditionQuery, { id: huntId });
  const handleClose = () => {
    commitFocus({ variables: { id: huntId, input: { focusOn: '' } } });
  };
  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.inline} />}>
          <HuntEditionContainer queryRef={queryRef} onClose={handleClose} controlledDial={EditEntityControlledDial} />
        </Suspense>
      )}
    </>
  );
};

export default HuntEdition;
