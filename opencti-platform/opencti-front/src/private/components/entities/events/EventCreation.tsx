import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import Drawer from '@components/common/drawer/Drawer';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { Add } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import { MESSAGING$, handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/MarkdownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { parse } from '../../../../utils/Time';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import type { Theme } from '../../../../components/Theme';
import { Option } from '../../common/form/ReferenceField';
import { EventCreationMutation, EventCreationMutation$variables } from './__generated__/EventCreationMutation.graphql';
import { EventsLinesPaginationQuery$variables } from './__generated__/EventsLinesPaginationQuery.graphql';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import CustomFileUploader from '../../common/files/CustomFileUploader';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const eventMutation = graphql`
  mutation EventCreationMutation($input: EventAddInput!) {
    eventAdd(input: $input) {
      id
      standard_id
      name
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
  confidence: number | undefined;
  event_types: string[];
  start_time: Date | null;
  stop_time: Date | null;
  createdBy: Option | undefined;
  objectMarking: Option[];
  objectLabel: Option[];
  externalReferences: { value: string }[];
  file: File | undefined;
}

interface EventFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  inputValue?: string;
}

export const EventCreationForm: FunctionComponent<EventFormProps> = ({
  updater,
  onReset,
  onCompleted,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  inputValue,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const basicShape = {
    name: Yup.string().min(2).required(t_i18n('This field is required')),
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
  };
  const eventValidator = useSchemaCreationValidation(EVENT_TYPE, basicShape);

  const [commit] = useMutation<EventCreationMutation>(eventMutation);

  const onSubmit: FormikConfig<EventAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const input: EventCreationMutation$variables['input'] = {
      name: values.name,
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
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'eventAdd');
        }
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        MESSAGING$.notifyError(`${error}`);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
        MESSAGING$.notifySuccess(`${t_i18n('entity_Event')} ${t_i18n('successfully created')}`);
      },
    });
  };

  const initialValues = useDefaultValues(EVENT_TYPE, {
    name: inputValue ?? '',
    description: '',
    event_types: [],
    start_time: null,
    confidence: undefined,
    stop_time: null,
    createdBy: defaultCreatedBy,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectLabel: [],
    externalReferences: [],
    file: undefined,
  });

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={eventValidator}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            detectDuplicate={['Event']}
          />
          <OpenVocabField
            label={t_i18n('Event types')}
            type="event-type-ov"
            name="event_types"
            containerStyle={fieldSpacingContainerStyle}
            multiple
            onChange={setFieldValue}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            multiline={true}
            rows={4}
            style={{ marginTop: 20 }}
          />
          <Field
            component={DateTimePickerField}
            name="start_time"
            textFieldProps={{
              label: t_i18n('Start date'),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
            }}
          />
          <Field
            component={DateTimePickerField}
            name="stop_time"
            textFieldProps={{
              label: t_i18n('End date'),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
            }}
          />
          <ConfidenceField
            entityType="Event"
            containerStyle={fieldSpacingContainerStyle}
          />
          <CreatedByField
            name="createdBy"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ObjectLabelField
            name="objectLabel"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.objectLabel}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={fieldSpacingContainerStyle}
          />
          <ExternalReferencesField
            name="externalReferences"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.externalReferences}
          />
          <CustomFileUploader setFieldValue={setFieldValue} />
          <div className={classes.buttons}>
            <Button
              variant="contained"
              onClick={handleReset}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t_i18n('Create')}
            </Button>
          </div>
        </Form>
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
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_events', paginationOptions, 'eventAdd');
  return (
    <Drawer
      title={t_i18n('Create an event')}
      controlledDial={({ onOpen }) => (
        <Button
          onClick={onOpen}
          variant='contained'
          color='primary'
          size='small'
          style={{
            marginLeft: '10px',
            padding: '7px 10px',
          }}
        >
          {t_i18n('Create')} {t_i18n('entity_Event')} <Add />
        </Button>
      )}
    >
      {({ onClose }) => (
        <EventCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
        />
      )}
    </Drawer>
  );
};

export default EventCreation;
