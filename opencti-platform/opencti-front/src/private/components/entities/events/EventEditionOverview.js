import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import * as R from 'ramda';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import StatusField from '../../common/form/StatusField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import { buildDate, parse } from '../../../../utils/Time';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

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
    $input: StixMetaRelationshipAddInput!
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

const eventValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  event_types: Yup.array().nullable(),
  description: Yup.string().nullable(),
  start_time: Yup.date()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .nullable(),
  stop_time: Yup.date()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .nullable(),
  x_opencti_workflow_id: Yup.object(),
});

const EventEditionOverviewComponent = (props) => {
  const { event, enableReferences, context, handleClose } = props;
  const { t } = useFormatter();

  const handleChangeFocus = (name) => commitMutation({
    mutation: eventEditionOverviewFocus,
    variables: {
      id: event.id,
      input: {
        focusOn: name,
      },
    },
  });

  const onSubmit = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc('start_time', parse(values.start_time).format()),
      R.assoc('stop_time', parse(values.stop_time).format()),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: eventMutationFieldPatch,
      variables: {
        id: event.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references,
      },
      setSubmitting,
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
      eventValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: eventMutationFieldPatch,
            variables: {
              id: event.id,
              input: { key: name, value: finalValue ?? '' },
            },
          });
        })
        .catch(() => false);
    }
  };

  const handleChangeCreatedBy = (name, value) => {
    if (!enableReferences) {
      commitMutation({
        mutation: eventMutationFieldPatch,
        variables: {
          id: event.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  };

  const handleChangeObjectMarking = (name, values) => {
    if (!enableReferences) {
      const currentMarkingDefinitions = R.pipe(
        R.pathOr([], ['objectMarking', 'edges']),
        R.map((n) => ({
          label: n.node.definition,
          value: n.node.id,
        })),
      )(event);
      const added = R.difference(values, currentMarkingDefinitions);
      const removed = R.difference(currentMarkingDefinitions, values);
      if (added.length > 0) {
        commitMutation({
          mutation: eventMutationRelationAdd,
          variables: {
            id: event.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-marking',
            },
          },
        });
      }
      if (removed.length > 0) {
        commitMutation({
          mutation: eventMutationRelationDelete,
          variables: {
            id: event.id,
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  };

  const createdBy = convertCreatedBy(event);
  const objectMarking = convertMarkings(event);
  const status = convertStatus(t, event);
  const initialValues = R.pipe(
    R.assoc('start_time', buildDate(event.start_time)),
    R.assoc('stop_time', buildDate(event.stop_time)),
    R.assoc('createdBy', createdBy),
    R.assoc('objectMarking', objectMarking),
    R.assoc('x_opencti_workflow_id', status),
    R.pick([
      'name',
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
        validationSchema={eventValidation(t)}
        onSubmit={onSubmit}
      >
        {({
          submitForm,
          isSubmitting,
          setFieldValue,
          values,
        }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t('Name')}
              fullWidth={true}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="name" />
              }
            />
            <OpenVocabField
              label={t('Event types')}
              type="event-type-ov"
              name="event_types"
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              onChange={(name, value) => setFieldValue(name, value)}
              containerStyle={fieldSpacingContainerStyle}
              variant="edit"
              multiple={true}
              editContext={context}
            />
            <Field
              component={MarkDownField}
              name="description"
              label={t('Description')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="description" />
              }
            />
            <Field
              component={DateTimePickerField}
              name="start_time"
              onFocus={handleChangeFocus}
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
              onFocus={handleChangeFocus}
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
                onFocus={handleChangeFocus}
                onChange={handleSubmitField}
                setFieldValue={setFieldValue}
                style={{ marginTop: 20 }}
                helpertext={
                  <SubscriptionFocus
                    context={context}
                    fieldName="x_opencti_workflow_id"
                  />
                }
              />
            )}
            <CreatedByField
              name="createdBy"
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              helpertext={
                <SubscriptionFocus context={context} fieldName="createdBy" />
              }
              onChange={handleChangeCreatedBy}
            />
            <ObjectMarkingField
              name="objectMarking"
              style={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldname="objectMarking"
                />
              }
              onChange={handleChangeObjectMarking}
            />
            {enableReferences && (
              <CommitMessage
                submitForm={submitForm}
                disabled={isSubmitting}
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
