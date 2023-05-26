import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { convertAssignees, convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { Option } from '../../common/form/ReferenceField';
import { adaptFieldValue } from '../../../../utils/String';
import { FeedbackEditionOverview_case$key } from './__generated__/FeedbackEditionOverview_case.graphql';
import TextField from '../../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import MarkDownField from '../../../../components/MarkDownField';
import RatingField from '../../../../components/RatingField';
import CommitMessage from '../../common/form/CommitMessage';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';

const feedbackMutationFieldPatch = graphql`
  mutation FeedbackEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...FeedbackEditionOverview_case
        ...Feedback_case
      }
    }
  }
`;

export const feedbackEditionOverviewFocus = graphql`
  mutation FeedbackEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    stixDomainObjectEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const feedbackEditionOverviewFragment = graphql`
  fragment FeedbackEditionOverview_case on Feedback {
    id
    name
    revoked
    description
    rating
    confidence
    x_opencti_stix_ids
    createdBy {
      ... on Identity {
        id
        name
        entity_type
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
    objectAssignee {
      edges {
        node {
          id
          name
          entity_type
        }
      }
    }
  }
`;

const feedbackMutationRelationAdd = graphql`
  mutation FeedbackEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    stixDomainObjectEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...FeedbackEditionOverview_case
        }
      }
    }
  }
`;

const feedbackMutationRelationDelete = graphql`
  mutation FeedbackEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixDomainObjectEdit(id: $id){
      relationDelete(
        toId: $toId
        relationship_type: $relationship_type
      ) {
        ...FeedbackEditionOverview_case
      }
    }
  }
`;

interface FeedbackEditionOverviewProps {
  feedbackRef: FeedbackEditionOverview_case$key;
  context:
  | readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[]
  | null;
  enableReferences?: boolean;
  handleClose: () => void;
}

interface FeedbackEditionFormValues {
  message?: string
  references?: Option[]
  createdBy?: Option
  x_opencti_workflow_id: Option
  objectMarking?: Option[]
}

const FeedbackEditionOverviewComponent: FunctionComponent<
FeedbackEditionOverviewProps
> = ({ feedbackRef, context, enableReferences = false, handleClose }) => {
  const { t } = useFormatter();
  const feedbackData = useFragment(feedbackEditionOverviewFragment, feedbackRef);

  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
    x_opencti_workflow_id: Yup.object(),
    rating: Yup.number(),
    confidence: Yup.number(),
  };
  const feedbackValidator = useSchemaEditionValidation('Feedback', basicShape);

  const queries = {
    fieldPatch: feedbackMutationFieldPatch,
    relationAdd: feedbackMutationRelationAdd,
    relationDelete: feedbackMutationRelationDelete,
    editionFocus: feedbackEditionOverviewFocus,
  };
  const editor = useFormEditor(feedbackData, enableReferences, queries, feedbackValidator);

  const onSubmit: FormikConfig<FeedbackEditionFormValues>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);

    const inputValues = Object.entries({
      ...otherValues,
      createdBy: values.createdBy?.value,
      x_opencti_workflow_id: values.x_opencti_workflow_id?.value,
      objectMarking: (values.objectMarking ?? []).map(({ value }) => value),
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));

    editor.fieldPatch({
      variables: {
        id: feedbackData.id,
        input: inputValues,
        commitMessage: commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references: commitReferences,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleSubmitField = (
    name: string,
    value: Option | string | string[] | number | number[] | null,
  ) => {
    if (!enableReferences) {
      let finalValue: unknown = value as string;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as Option).value;
      }
      feedbackValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: feedbackData.id,
              input: [{ key: name, value: finalValue || '' }],
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = {
    name: feedbackData.name,
    description: feedbackData.description,
    rating: feedbackData.rating,
    confidence: feedbackData.confidence,
    createdBy: convertCreatedBy(feedbackData) as Option,
    objectMarking: convertMarkings(feedbackData),
    objectAssignee: convertAssignees(feedbackData),
    x_opencti_workflow_id: convertStatus(t, feedbackData) as Option,
  };
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={feedbackValidator}
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
            style={fieldSpacingContainerStyle}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
          />
          <Field
            component={MarkDownField}
            name="description"
            label={t('Description')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={fieldSpacingContainerStyle}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
            }
          />
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="Feedback"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          <RatingField
            label={t('Rating')}
            rating={feedbackData.rating}
            size="small"
            style={fieldSpacingContainerStyle}
            handleOnChange={(newValue) => handleSubmitField('rating', String(newValue))
            }
          />
          <ObjectAssigneeField
            name="objectAssignee"
            style={fieldSpacingContainerStyle}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectAssignee" />
            }
            onChange={editor.changeAssignee}
          />
          {feedbackData.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Feedback"
              onFocus={editor.changeFocus}
              onChange={handleSubmitField}
              setFieldValue={setFieldValue}
              style={fieldSpacingContainerStyle}
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
              id={feedbackData.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default FeedbackEditionOverviewComponent;
