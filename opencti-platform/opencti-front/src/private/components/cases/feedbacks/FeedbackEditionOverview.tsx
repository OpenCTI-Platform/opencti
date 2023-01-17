import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionFocus } from '../../../../components/Subscription';
import {
  convertAssignees,
  convertCreatedBy,
  convertMarkings,
  convertStatus,
} from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { Option } from '../../common/form/ReferenceField';
import { adaptFieldValue } from '../../../../utils/String';
import { FeedbackEditionOverview_case$key } from './__generated__/FeedbackEditionOverview_case.graphql';
import TextField from '../../../../components/TextField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import MarkDownField from '../../../../components/MarkDownField';
import RatingField from '../../../../components/RatingField';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';

const feedbackMutationFieldPatch = graphql`
  mutation FeedbackEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    caseFieldPatch(
      id: $id
      input: $input
      commitMessage: $commitMessage
      references: $references
    ) {
      ...FeedbackEditionOverview_case
      ...Feedback_case
    }
  }
`;

export const feedbackEditionOverviewFocus = graphql`
  mutation FeedbackEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    caseContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const feedbackEditionOverviewFragment = graphql`
  fragment FeedbackEditionOverview_case on Case {
    id
    name
    case_type
    priority
    severity
    revoked
    description
    rating
    creator {
      id
      name
    }
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
    $input: StixMetaRelationshipAddInput!
  ) {
    caseRelationAdd(id: $id, input: $input) {
      from {
        ...FeedbackEditionOverview_case
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
    caseRelationDelete(
      id: $id
      toId: $toId
      relationship_type: $relationship_type
    ) {
      ...FeedbackEditionOverview_case
    }
  }
`;

const caseValidation = (t: (v: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  priority: Yup.string().nullable(),
  severity: Yup.string().nullable(),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
  x_opencti_workflow_id: Yup.object(),
  rating: Yup.number(),
});

interface FeedbackEditionOverviewProps {
  caseRef: FeedbackEditionOverview_case$key;
  context:
  | readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[]
  | null;
  enableReferences?: boolean;
  handleClose: () => void;
}

interface CaseEditionFormValues {
  x_opencti_workflow_id:
  | string
  | { label: string; color: string; value: string; order: string };
}

const CaseEditionOverviewComponent: FunctionComponent<
FeedbackEditionOverviewProps
> = ({ caseRef, context, enableReferences = false, handleClose }) => {
  const { t } = useFormatter();
  const caseData = useFragment(feedbackEditionOverviewFragment, caseRef);

  const createdBy = convertCreatedBy(caseData);
  const objectMarking = convertMarkings(caseData);
  const objectAssignee = convertAssignees(caseData);
  const status = convertStatus(t, caseData);

  const queries = {
    fieldPatch: feedbackMutationFieldPatch,
    relationAdd: feedbackMutationRelationAdd,
    relationDelete: feedbackMutationRelationDelete,
    editionFocus: feedbackEditionOverviewFocus,
  };
  const editor = useFormEditor(caseData, enableReferences, queries);

  const onSubmit: FormikConfig<CaseEditionFormValues>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    const inputValues = Object.entries({
      x_opencti_workflow_id: values.x_opencti_workflow_id,
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));
    editor.fieldPatch({
      variables: { id: caseData.id, input: inputValues },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleSubmitField = (
    name: string,
    value: Option | string | string[] | null,
  ) => {
    if (!enableReferences) {
      let finalValue: unknown = value as string;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as Option).value;
      }
      caseValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: caseData.id,
              input: { key: name, value: finalValue || '' },
            },
          });
        })
        .catch(() => false);
    }
  };
  const initialValues = {
    name: caseData.name,
    description: caseData.description,
    priority: caseData.priority,
    severity: caseData.severity,
    rating: caseData.rating,
    createdBy,
    objectMarking,
    objectAssignee,
    x_opencti_workflow_id: status,
  };
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues as never}
      validationSchema={caseValidation(t)}
      onSubmit={onSubmit}
    >
      {({ setFieldValue }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <OpenVocabField
            label={t('Case priority')}
            type="case_priority_ov"
            name="priority"
            onSubmit={handleSubmitField}
            onChange={(name, value) => setFieldValue(name, value)}
            variant="edit"
            containerStyle={{ width: '100%' }}
            multiple={false}
            editContext={context}
          />
          <OpenVocabField
            label={t('Case severity')}
            type="case_severity_ov"
            name="severity"
            onSubmit={handleSubmitField}
            onChange={(name, value) => setFieldValue(name, value)}
            variant="edit"
            containerStyle={fieldSpacingContainerStyle}
            multiple={false}
            editContext={context}
          />
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
          <ObjectAssigneeField
            name="objectAssignee"
            style={{ marginTop: 20, width: '100%' }}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectAssignee" />
            }
            onChange={editor.changeAssignee}
          />
          {caseData.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Case"
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
          <RatingField
            label={t('Rating')}
            rating={caseData.rating}
            size="small"
            style={fieldSpacingContainerStyle}
            handleOnChange={(newValue) => handleSubmitField('rating', String(newValue))
            }
          />
        </Form>
      )}
    </Formik>
  );
};

export default CaseEditionOverviewComponent;
