import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import * as R from 'ramda';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/MarkdownField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import StatusField from '../../common/form/StatusField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import { buildDate, parse } from '../../../../utils/Time';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';

const eventMutationFieldPatch = graphql`
  mutation EventEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
      eventFieldPatch(
        id: $id
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...EventEditionOverview_event
        ...Event_event
      }
    }
`;

export const eventEditionOverviewFocus = graphql`
  mutation EventEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    eventContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const eventMutationRelationAdd = graphql`
  mutation EventEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    eventRelationAdd(id: $id, input: $input) {
      from {
        ...EventEditionOverview_event
      }
    }
  }
`;

const eventMutationRelationDelete = graphql`
  mutation EventEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    eventRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
      ...EventEditionOverview_event
    }
  }
`;

const EventEditionOverviewComponent = (props) => {
  const { event, enableReferences, context, handleClose } = props;
  const { t } = useFormatter();

  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
    event_types: Yup.array().nullable(),
    start_time: Yup.date().typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')).nullable(),
    stop_time: Yup.date()
      .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .min(Yup.ref('start_time'), "The end date can't be before start date")
      .nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const eventValidator = useSchemaEditionValidation('Event', basicShape);

  const queries = {
    fieldPatch: eventMutationFieldPatch,
    relationAdd: eventMutationRelationAdd,
    relationDelete: eventMutationRelationDelete,
    editionFocus: eventEditionOverviewFocus,
  };
  const editor = useFormEditor(event, enableReferences, queries, eventValidator);

  const onSubmit = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc('start_time', parse(values.start_time).format()),
      R.assoc('stop_time', parse(values.stop_time).format()),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    editor.fieldPatch({
      variables: {
        id: event.id,
        input: inputValues,
        commitMessage: commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleSubmitField = (name, value) => {
    if (!enableReferences) {
      let finalValue = value;
      if (name === 'x_opencti_workflow_id') {
        finalValue = value.value;
      }
      editor.fieldPatch({
        variables: {
          id: event.id,
          input: { key: name, value: finalValue ?? '' },
        },
      });
    }
  };

  const initialValues = R.pipe(
    R.assoc('start_time', buildDate(event.start_time)),
    R.assoc('stop_time', buildDate(event.stop_time)),
    R.assoc('createdBy', convertCreatedBy(event)),
    R.assoc('objectMarking', convertMarkings(event)),
    R.assoc('x_opencti_workflow_id', convertStatus(t, event)),
    R.assoc('references', []),
    R.pick([
      'name',
      'references',
      'event_types',
      'description',
      'start_time',
      'stop_time',
      'createdBy',
      'objectMarking',
      'x_opencti_workflow_id',
    ]),
  )(event);
  return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={eventValidator}
        onSubmit={onSubmit}
      >
        {({
          submitForm,
          isSubmitting,
          setFieldValue,
          values,
          isValid,
          dirty,
        }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t('Name')}
              fullWidth={true}
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="name" />
              }
            />
            <OpenVocabField
              label={t('Event types')}
              type="event-type-ov"
              name="event_types"
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              onChange={(name, value) => setFieldValue(name, value)}
              containerStyle={fieldSpacingContainerStyle}
              variant="edit"
              multiple={true}
              editContext={context}
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t('Description')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="description" />
              }
            />
            <Field
              component={DateTimePickerField}
              name="start_time"
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              TextFieldProps={{
                label: t('Start date'),
                variant: 'standard',
                fullWidth: true,
                style: { marginTop: 20 },
                helperText: (
                  <SubscriptionFocus context={context} fieldName="start_date" />
                ),
              }}
            />
            <Field
              component={DateTimePickerField}
              name="stop_time"
              onFocus={editor.changeFocus}
              onSubmit={handleSubmitField}
              TextFieldProps={{
                label: t('End date'),
                variant: 'standard',
                fullWidth: true,
                style: { marginTop: 20 },
                helperText: (
                  <SubscriptionFocus context={context} fieldName="end_date" />
                ),
              }}
            />
            {event.workflowEnabled && (
              <StatusField
                name="x_opencti_workflow_id"
                type="Event"
                onFocus={editor.changeFocus}
                onChange={handleSubmitField}
                setFieldValue={setFieldValue}
                style={{ marginTop: 20 }}
                helpertext={
                  <SubscriptionFocus context={context} fieldName="x_opencti_workflow_id" />
                }
              />
            )}
            <CreatedByField
              name="createdBy"
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
              helpertext={
                <SubscriptionFocus context={context} fieldName="createdBy" />
              }
              onChange={editor.changeCreated}
            />
            <ObjectMarkingField
              name="objectMarking"
              style={fieldSpacingContainerStyle}
              helpertext={
                <SubscriptionFocus context={context} fieldname="objectMarking" />
              }
              onChange={editor.changeMarking}
            />
            {enableReferences && (
              <CommitMessage
                submitForm={submitForm}
                disabled={isSubmitting || !isValid || !dirty}
                setFieldValue={setFieldValue}
                open={false}
                values={values.references}
                id={event.id}
              />
            )}
          </Form>
        )}
      </Formik>
  );
};

export default createFragmentContainer(EventEditionOverviewComponent, {
  event: graphql`
      fragment EventEditionOverview_event on Event {
        id
        name
        event_types
        description
        start_time
        stop_time
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        objectMarking {
          edges {
            node {
              id
              definition_type
              definition
              x_opencti_order
              x_opencti_color
            }
          }
        }
        status {
          id
          order
          template {
            name
            color
          }
        }
        workflowEnabled
      }
    `,
});
