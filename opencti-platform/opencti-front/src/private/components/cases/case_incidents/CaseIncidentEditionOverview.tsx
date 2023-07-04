import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import * as Yup from 'yup';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/MarkdownField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';
import { convertAssignees, convertCreatedBy, convertMarkings, convertParticipants, convertStatus } from '../../../../utils/edition';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';
import ConfidenceField from '../../common/form/ConfidenceField';
import CreatedByField from '../../common/form/CreatedByField';
import { ExternalReferencesValues } from '../../common/form/ExternalReferencesField';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { Option } from '../../common/form/ReferenceField';
import StatusField from '../../common/form/StatusField';
import { CaseIncidentEditionOverview_case$key } from './__generated__/CaseIncidentEditionOverview_case.graphql';
import { TasksFiltering } from '../tasks/__generated__/CaseTasksLinesQuery.graphql';
import ObjectParticipantField from '../../common/form/ObjectParticipantField';

export const caseIncidentMutationFieldPatch = graphql`
  mutation CaseIncidentEditionOverviewCaseFieldPatchMutation(
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
        ...CaseIncidentEditionOverview_case
        ...CaseUtils_case
      }
    }
  }
`;

export const caseIncidentEditionOverviewFocus = graphql`
  mutation CaseIncidentEditionOverviewCaseFocusMutation(
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

const caseIncidentEditionOverviewFragment = graphql`
  fragment CaseIncidentEditionOverview_case on CaseIncident {
    id
    name
    severity
    priority
    revoked
    description
    rating
    confidence
    created
    response_types
    creators {
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
    objectParticipant {
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

const caseIncidentMutationRelationAdd = graphql`
  mutation CaseIncidentEditionOverviewCaseRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    stixDomainObjectEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...CaseIncidentEditionOverview_case
        }
      }
    }
  }
`;

const caseIncidentMutationRelationDelete = graphql`
  mutation CaseIncidentEditionOverviewCaseRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixDomainObjectEdit(id: $id){
      relationDelete(
        toId: $toId
        relationship_type: $relationship_type
      ) {
        ...CaseIncidentEditionOverview_case
      }
    }
  }
`;

interface CaseIncidentEditionOverviewProps {
  caseRef: CaseIncidentEditionOverview_case$key
  context: ReadonlyArray<{
    readonly focusOn: string | null
    readonly name: string
  }> | null
  enableReferences?: boolean
  handleClose: () => void
  tasksPaginationOptions?: { filters: TasksFiltering[] }
}

interface CaseIncidentEditionFormValues {
  message?: string
  createdBy?: Option
  objectMarking?: Option[]
  objectAssignee?: Option[]
  objectParticipant?: Option[]
  x_opencti_workflow_id: Option
  references: ExternalReferencesValues | undefined
}

const CaseIncidentEditionOverview: FunctionComponent<CaseIncidentEditionOverviewProps> = ({
  caseRef,
  context,
  enableReferences = false,
  handleClose,
}) => {
  const { t } = useFormatter();
  const caseData = useFragment(caseIncidentEditionOverviewFragment, caseRef);

  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    severity: Yup.string().nullable(),
    priority: Yup.string().nullable(),
    response_types: Yup.array(),
    description: Yup.string().nullable(),
    x_opencti_workflow_id: Yup.object().nullable(),
    rating: Yup.number().nullable(),
    confidence: Yup.number().nullable(),
  };
  const caseIncidentValidator = useSchemaEditionValidation('Case-Incident', basicShape);

  const queries = {
    fieldPatch: caseIncidentMutationFieldPatch,
    relationAdd: caseIncidentMutationRelationAdd,
    relationDelete: caseIncidentMutationRelationDelete,
    editionFocus: caseIncidentEditionOverviewFocus,
  };
  const editor = useFormEditor(caseData, enableReferences, queries, caseIncidentValidator);

  const onSubmit: FormikConfig<CaseIncidentEditionFormValues>['onSubmit'] = (values, { setSubmitting }) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);
    const inputValues = Object.entries({
      ...otherValues,
      createdBy: values.createdBy?.value,
      x_opencti_workflow_id: values.x_opencti_workflow_id?.value,
      objectMarking: (values.objectMarking ?? []).map(({ value }) => value),
      objectAssignee: (values.objectAssignee ?? []).map(({ value }) => value),
      objectParticipant: (values.objectParticipant ?? []).map(({ value }) => value),
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));
    editor.fieldPatch({
      variables: {
        id: caseData.id,
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

  const handleSubmitField = (name: string, value: Option | string | string[] | number | number[] | null) => {
    if (!enableReferences) {
      let finalValue: unknown = value as string;
      if (['x_opencti_workflow_id'].includes(name)) {
        finalValue = (value as Option).value;
      }
      caseIncidentValidator
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
    created: caseData.created,
    severity: caseData.severity,
    response_types: caseData.response_types ?? [],
    confidence: caseData.confidence,
    createdBy: convertCreatedBy(caseData),
    objectMarking: convertMarkings(caseData),
    objectAssignee: convertAssignees(caseData),
    objectParticipant: convertParticipants(caseData),
    x_opencti_workflow_id: convertStatus(t, caseData) as Option,
    references: [],
  };
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues as never}
      validationSchema={caseIncidentValidator}
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
            onSubmit={editor.changeField}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
            style={{ marginBottom: '20px' }}
          />
          <Field
            component={DateTimePickerField}
            name="created"
            onFocus={editor.changeFocus}
            onSubmit={editor.changeField}
            TextFieldProps={{
              label: t('Incident date'),
              variant: 'standard',
              fullWidth: true,
              helperText: (
                <SubscriptionFocus context={context} fieldName="created" />
              ),
            }}
            containerStyle={fieldSpacingContainerStyle}
          />
          <OpenVocabField
            label={t('Case severity')}
            type="case_severity_ov"
            name="severity"
            onSubmit={handleSubmitField}
            onChange={setFieldValue}
            variant="edit"
            containerStyle={fieldSpacingContainerStyle}
            multiple={false}
            editContext={context}
          />
          <OpenVocabField
            label={t('Case priority')}
            type="case_priority_ov"
            name="priority"
            onSubmit={handleSubmitField}
            onChange={setFieldValue}
            variant="edit"
            containerStyle={fieldSpacingContainerStyle}
            multiple={false}
            editContext={context}
          />
          <OpenVocabField
            label={t('Response type')}
            type="incident_response_types_ov"
            name="response_types"
            onSubmit={handleSubmitField}
            onChange={setFieldValue}
            variant="edit"
            containerStyle={fieldSpacingContainerStyle}
            multiple
            editContext={context}
          />
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={editor.changeField}
            entityType="Case-Incident"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t('Description')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={fieldSpacingContainerStyle}
            onFocus={editor.changeFocus}
            onSubmit={editor.changeField}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
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
          <ObjectParticipantField
            name="objectParticipant"
            style={fieldSpacingContainerStyle}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectParticipant" />
            }
            onChange={editor.changeParticipant}
          />
          {caseData.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Case-Incident"
              onFocus={editor.changeFocus}
              onChange={editor.changeField}
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
              id={caseData.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default CaseIncidentEditionOverview;
