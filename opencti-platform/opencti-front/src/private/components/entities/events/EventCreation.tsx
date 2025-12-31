import React, { FunctionComponent, useEffect, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { parse } from '../../../../utils/Time';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import { EventCreationMutation, EventCreationMutation$variables } from './__generated__/EventCreationMutation.graphql';
import { EventsLinesPaginationQuery$variables } from './__generated__/EventsLinesPaginationQuery.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import useBulkCommit from '../../../../utils/hooks/useBulkCommit';
import { splitMultilines } from '../../../../utils/String';
import BulkTextModal from '../../../../components/fields/BulkTextField/BulkTextModal';
import ProgressBar from '../../../../components/ProgressBar';
import BulkTextField from '../../../../components/fields/BulkTextField/BulkTextField';
import BulkTextModalButton from '../../../../components/fields/BulkTextField/BulkTextModalButton';

const eventMutation = graphql`
  mutation EventCreationMutation($input: EventAddInput!) {
    eventAdd(input: $input) {
      id
      standard_id
      name
      representative {
        main
      }
      description
      confidence
      entity_type
      parent_types
      ...EventLine_node
    }
  }
`;

const EVENT_TYPE = 'Event';

interface EventAddInput {
  name: string;
  description: string;
  confidence: number | null;
  event_types: string[];
  start_time: Date | null;
  stop_time: Date | null;
  createdBy: FieldOption | undefined;
  objectMarking: FieldOption[];
  objectLabel: FieldOption[];
  externalReferences: { value: string }[];
  file: File | null;
}

interface EventFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: FieldOption;
  defaultMarkingDefinitions?: FieldOption[];
  inputValue?: string;
  bulkModalOpen?: boolean;
  onBulkModalClose: () => void;
}

export const EventCreationForm: FunctionComponent<EventFormProps> = ({
  updater,
  onReset,
  onCompleted,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  inputValue,
  bulkModalOpen = false,
  onBulkModalClose,
}) => {
  const { t_i18n } = useFormatter();
  const [progressBarOpen, setProgressBarOpen] = useState(false);

  const { mandatoryAttributes } = useIsMandatoryAttribute(EVENT_TYPE);
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    event_types: Yup.array().nullable(),
    start_time: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .nullable(),
    stop_time: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .min(Yup.ref('start_time'), 'The end date can\'t be before start date')
      .nullable(),
    createdBy: Yup.object().nullable(),
    objectMarking: Yup.array().nullable(),
  }, mandatoryAttributes);
  const eventValidator = useDynamicSchemaCreationValidation(mandatoryAttributes, basicShape);

  const [commit] = useApiMutation<EventCreationMutation>(
    eventMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Event')} ${t_i18n('successfully created')}` },
  );
  const {
    bulkCommit,
    bulkCount,
    bulkCurrentCount,
    BulkResult,
    resetBulk,
  } = useBulkCommit<EventCreationMutation>({
    commit,
    relayUpdater: (store) => {
      if (updater) {
        updater(store, 'eventAdd');
      }
    },
  });

  useEffect(() => {
    if (bulkCount > 1) {
      setProgressBarOpen(true);
    }
  }, [bulkCount]);

  const onSubmit: FormikConfig<EventAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const allNames = splitMultilines(values.name);
    const variables: EventCreationMutation$variables[] = allNames.map((name) => ({
      input: {
        name,
        description: values.description,
        event_types: values.event_types,
        confidence: parseInt(String(values.confidence), 10),
        start_time: values.start_time ? parse(values.start_time).format() : null,
        stop_time: values.stop_time ? parse(values.stop_time).format() : null,
        createdBy: values.createdBy?.value,
        objectMarking: values.objectMarking.map((v) => v.value),
        objectLabel: values.objectLabel.map((v) => v.value),
        externalReferences: values.externalReferences.map(({ value }) => value),
        file: values.file,
      },
    }));

    bulkCommit({
      variables,
      onStepError: (error) => {
        handleErrorInForm(error, setErrors);
      },
      onCompleted: (total: number) => {
        setSubmitting(false);
        if (total < 2) {
          resetForm();
          onCompleted?.();
        }
      },
    });
  };

  const initialValues = useDefaultValues(EVENT_TYPE, {
    name: inputValue ?? '',
    description: '',
    event_types: [],
    start_time: null,
    confidence: null,
    stop_time: null,
    createdBy: defaultCreatedBy ?? undefined, // undefined for Require Fields Flagging, if Configured Mandatory Field
    objectMarking: defaultMarkingDefinitions ?? [],
    objectLabel: [],
    externalReferences: [],
    file: null,
  });

  return (
    <Formik<EventAddInput>
      initialValues={initialValues}
      validationSchema={eventValidator}
      validateOnChange={false}
      validateOnBlur={false}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values, resetForm }) => (
        <>
          <BulkTextModal
            open={bulkModalOpen}
            onClose={onBulkModalClose}
            onValidate={async (val) => {
              await setFieldValue('name', val);
              if (splitMultilines(val).length > 1) {
                await setFieldValue('file', null);
              }
            }}
            formValue={values.name}
          />
          <ProgressBar
            open={progressBarOpen}
            value={(bulkCurrentCount / bulkCount) * 100}
            label={`${bulkCurrentCount}/${bulkCount}`}
            title={t_i18n('Create multiple entities')}
            onClose={() => {
              setProgressBarOpen(false);
              resetForm();
              resetBulk();
              onCompleted?.();
            }}
          >
            <BulkResult variablesToString={(v) => v.input.name} />
          </ProgressBar>
          <Form>
            <Field
              component={BulkTextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              required={(mandatoryAttributes.includes('name'))}
              fullWidth={true}
              detectDuplicate={['Event']}
            />
            <OpenVocabField
              label={t_i18n('Event types')}
              type="event-type-ov"
              name="event_types"
              required={(mandatoryAttributes.includes('event_types'))}
              containerStyle={fieldSpacingContainerStyle}
              multiple
              onChange={setFieldValue}
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              required={(mandatoryAttributes.includes('description'))}
              fullWidth={true}
              multiline={true}
              rows={4}
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={DateTimePickerField}
              name="start_time"
              textFieldProps={{
                label: t_i18n('Start date'),
                required: (mandatoryAttributes.includes('start_time')),
                variant: 'standard',
                fullWidth: true,
                style: { ...fieldSpacingContainerStyle },
              }}
            />
            <Field
              component={DateTimePickerField}
              name="stop_time"
              textFieldProps={{
                label: t_i18n('End date'),
                required: (mandatoryAttributes.includes('stop_time')),
                variant: 'standard',
                fullWidth: true,
                style: { ...fieldSpacingContainerStyle },
              }}
            />
            <ConfidenceField
              entityType="Event"
              containerStyle={fieldSpacingContainerStyle}
            />
            <CreatedByField
              name="createdBy"
              required={(mandatoryAttributes.includes('createdBy'))}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            <ObjectLabelField
              name="objectLabel"
              required={(mandatoryAttributes.includes('objectLabel'))}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
              values={values.objectLabel}
            />
            <ObjectMarkingField
              name="objectMarking"
              required={(mandatoryAttributes.includes('objectMarking'))}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            <ExternalReferencesField
              name="externalReferences"
              required={(mandatoryAttributes.includes('externalReferences'))}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
              values={values.externalReferences}
            />
            <Field
              component={CustomFileUploader}
              name="file"
              setFieldValue={setFieldValue}
              disabled={splitMultilines(values.name).length > 1}
              noFileSelectedLabel={splitMultilines(values.name).length > 1
                ? t_i18n('File upload not allowed in bulk creation')
                : undefined
              }
            />
            <div style={{
              marginTop: '20px',
              textAlign: 'right',
            }}
            >
              <Button
                variant="secondary"
                onClick={handleReset}
                disabled={isSubmitting}
                sx={{ marginLeft: 2 }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                onClick={submitForm}
                disabled={isSubmitting}
                sx={{ marginLeft: 2 }}
              >
                {t_i18n('Create')}
              </Button>
            </div>
          </Form>
        </>
      )}
    </Formik>
  );
};

const EventCreation = ({
  paginationOptions,
}: {
  paginationOptions: EventsLinesPaginationQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const [bulkOpen, setBulkOpen] = useState(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_events', paginationOptions, 'eventAdd');

  const CreateEventControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType="Event" {...props} />
  );
  return (
    <Drawer
      title={t_i18n('Create an event')}
      header={<BulkTextModalButton onClick={() => setBulkOpen(true)} />}
      controlledDial={CreateEventControlledDial}
    >
      {({ onClose }) => (
        <EventCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
        />
      )}
    </Drawer>
  );
};

export default EventCreation;
