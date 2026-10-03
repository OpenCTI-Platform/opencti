import React from 'react';
import type { PayloadError } from 'relay-runtime';
import { Field, Form, Formik, FormikHelpers } from 'formik';
import * as Yup from 'yup';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import SelectFieldFds, { SelectItem } from '../../../../components/fields/SelectFieldFds';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';
import TextareaField from '../../../../components/TextareaField';
import SwitchField from '../../../../components/fields/SwitchField';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import ObjectMarkingField from '../form/ObjectMarkingField';
import { fieldSpacingContainerStyle, type FieldOption } from '../../../../utils/field';
import { handleErrorInForm, MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { notifyTimelineMutationErrors, timelineEventAddMutation, timelineEventEditMutation } from './ContainerTimelineMutations';
import type {
  ContainerTimelineMutationsAddMutation,
  TimelineEventKind,
  TimelineLane as GqlTimelineLane,
  TimelinePrecision as GqlTimelinePrecision,
} from './__generated__/ContainerTimelineMutationsAddMutation.graphql';
import type { ContainerTimelineMutationsEditMutation } from './__generated__/ContainerTimelineMutationsEditMutation.graphql';
import type { TimelineEventDetails } from './ContainerTimelineEventDrawer';
import {
  TIMELINE_KIND_LABELS,
  TIMELINE_LANE_LABELS,
  TIMELINE_LANES,
  TIMELINE_MILESTONE_KINDS,
  TIMELINE_PRECISION_LABELS,
  TIMELINE_PRECISIONS,
  TIMELINE_KINDS,
} from './timelineUtils';

interface TimelineEventFormValues {
  title: string;
  event_time: Date | null;
  event_end_time: Date | null;
  precision: string;
  lane: string;
  kind: string;
  description: string;
  annotation: string;
  pinned: boolean;
  objectMarking: FieldOption[];
}

interface ContainerTimelineEventFormProps {
  containerId: string;
  open: boolean;
  // Manual event being edited, null to add a new one
  event: TimelineEventDetails | null;
  onClose: () => void;
  onSaved: () => void;
}

// Milestone kinds first, then the kinds an analyst can reproduce by hand
const KIND_OPTIONS = [...TIMELINE_MILESTONE_KINDS, ...TIMELINE_KINDS.filter((kind) => !(TIMELINE_MILESTONE_KINDS as readonly string[]).includes(kind))];

const toDate = (value: string | null | undefined) => (value ? new Date(value) : null);

const ContainerTimelineEventForm = ({ containerId, open, event, onClose, onSaved }: ContainerTimelineEventFormProps) => {
  const { t_i18n } = useFormatter();
  const [commitAdd] = useApiMutation<ContainerTimelineMutationsAddMutation>(timelineEventAddMutation);
  const [commitEdit] = useApiMutation<ContainerTimelineMutationsEditMutation>(timelineEventEditMutation);
  const isEdition = !!event;

  const validation = Yup.object().shape({
    title: Yup.string().trim().required(t_i18n('This field is required')).max(512, t_i18n('The value is too long')),
    event_time: Yup.date().nullable().required(t_i18n('This field is required')).typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    event_end_time: Yup.date()
      .nullable()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .min(Yup.ref('event_time'), t_i18n('The end time must be after the start time')),
    description: Yup.string().nullable().max(10000, t_i18n('The value is too long')),
    annotation: Yup.string().nullable().max(10000, t_i18n('The value is too long')),
  });

  const initialValues: TimelineEventFormValues = {
    title: event?.title ?? '',
    event_time: toDate(event?.event_time) ?? new Date(),
    event_end_time: toDate(event?.event_end_time),
    precision: event?.precision ?? 'exact',
    lane: event?.lane ?? 'response',
    kind: event?.kind ?? 'milestone',
    description: event?.description ?? '',
    annotation: event?.annotation ?? '',
    pinned: event?.pinned ?? false,
    objectMarking: (event?.objectMarking ?? []).map((marking) => ({
      value: marking.id,
      label: marking.definition ?? marking.id,
      color: marking.x_opencti_color ?? undefined,
      definition_type: marking.definition_type ?? undefined,
      x_opencti_order: marking.x_opencti_order,
    })),
  };

  const onSubmit = (values: TimelineEventFormValues, { setSubmitting, setErrors, resetForm }: FormikHelpers<TimelineEventFormValues>) => {
    const common = {
      title: values.title.trim(),
      event_time: (values.event_time as Date).toISOString(),
      precision: values.precision as GqlTimelinePrecision,
      lane: values.lane as GqlTimelineLane,
      kind: values.kind as TimelineEventKind,
      description: values.description || null,
      annotation: values.annotation || null,
      objectMarking: values.objectMarking.map((marking) => marking.value),
    };
    const onCompleted = (_: unknown, errors: readonly PayloadError[] | null) => {
      setSubmitting(false);
      if (notifyTimelineMutationErrors(errors)) return;
      resetForm();
      MESSAGING$.notifySuccess(isEdition ? t_i18n('The milestone has been updated') : t_i18n('The milestone has been added to the timeline'));
      onSaved();
      onClose();
    };
    const onError = (error: Error) => {
      handleErrorInForm(error, setErrors);
      setSubmitting(false);
    };
    if (event) {
      commitEdit({
        variables: {
          id: event.id,
          input: {
            ...common,
            event_end_time: values.event_end_time ? values.event_end_time.toISOString() : null,
            clear_event_end_time: !values.event_end_time,
          },
        },
        onCompleted,
        onError,
      });
    } else {
      commitAdd({
        variables: {
          input: {
            ...common,
            container_id: containerId,
            event_end_time: values.event_end_time ? values.event_end_time.toISOString() : null,
            pinned: values.pinned,
          },
        },
        onCompleted,
        onError,
      });
    }
  };

  return (
    <Drawer title={isEdition ? t_i18n('Update the milestone') : t_i18n('Add a milestone')} open={open} onClose={onClose}>
      <Formik<TimelineEventFormValues>
        initialValues={initialValues}
        enableReinitialize={true}
        validationSchema={validation}
        onSubmit={onSubmit}
        onReset={onClose}
      >
        {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
          <Form data-testid="timeline-event-form">
            <Field component={TextField} variant="outlined" name="title" label={t_i18n('Title')} required fullWidth={true} />
            <Field
              component={DateTimePickerField}
              name="event_time"
              required
              textFieldProps={{ label: t_i18n('Start date'), variant: 'outlined', fullWidth: true, style: { marginTop: 20 } }}
            />
            <Field
              component={DateTimePickerField}
              name="event_end_time"
              textFieldProps={{ label: t_i18n('End date'), variant: 'outlined', fullWidth: true, style: { marginTop: 20 } }}
            />
            <Field component={SelectFieldFds} name="precision" label={t_i18n('Precision')} fullWidth={true} containerstyle={fieldSpacingContainerStyle}>
              {TIMELINE_PRECISIONS.map((precision) => (
                <SelectItem key={precision} value={precision}>{t_i18n(TIMELINE_PRECISION_LABELS[precision])}</SelectItem>
              ))}
            </Field>
            <Field component={SelectFieldFds} name="lane" label={t_i18n('Lane')} fullWidth={true} containerstyle={fieldSpacingContainerStyle}>
              {TIMELINE_LANES.map((lane) => (
                <SelectItem key={lane} value={lane}>{t_i18n(TIMELINE_LANE_LABELS[lane])}</SelectItem>
              ))}
            </Field>
            <Field component={SelectFieldFds} name="kind" label={t_i18n('Kind')} fullWidth={true} containerstyle={fieldSpacingContainerStyle}>
              {KIND_OPTIONS.map((kind) => (
                <SelectItem key={kind} value={kind}>{t_i18n(TIMELINE_KIND_LABELS[kind])}</SelectItem>
              ))}
            </Field>
            <Field component={MarkdownField} name="description" label={t_i18n('Description')} fullWidth={true} multiline={true} rows="4" style={{ marginTop: 20 }} />
            <Field component={TextareaField} name="annotation" label={t_i18n('Annotation')} className="mt-5" rows={3} />
            <ObjectMarkingField
              name="objectMarking"
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            {!isEdition && (
              <Field component={SwitchField} type="checkbox" name="pinned" label={t_i18n('Pin on the timeline')} containerstyle={fieldSpacingContainerStyle} />
            )}
            <FormButtonContainer>
              <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>{t_i18n('Cancel')}</Button>
              <Button onClick={submitForm} disabled={isSubmitting} data-testid="timeline-event-form-submit">
                {isEdition ? t_i18n('Update') : t_i18n('Add')}
              </Button>
            </FormButtonContainer>
          </Form>
        )}
      </Formik>
    </Drawer>
  );
};

export default ContainerTimelineEventForm;
