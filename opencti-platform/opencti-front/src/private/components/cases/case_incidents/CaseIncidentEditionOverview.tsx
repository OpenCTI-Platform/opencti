import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import * as Yup from 'yup';
import { GenericContext } from '@components/common/model/GenericContextModel';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';
import { convertAssignees, convertCreatedBy, convertMarkings, convertParticipants, convertStatus } from '../../../../utils/edition';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { useDynamicSchemaEditionValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';
import ConfidenceField from '../../common/form/ConfidenceField';
import CreatedByField from '../../common/form/CreatedByField';
import { ExternalReferencesValues } from '../../common/form/ExternalReferencesField';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import OpenVocabField from '../../common/form/OpenVocabField';
import StatusField from '../../common/form/StatusField';
import { CaseIncidentEditionOverview_case$key } from './__generated__/CaseIncidentEditionOverview_case.graphql';
import ObjectParticipantField from '../../common/form/ObjectParticipantField';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

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
        x_opencti_graph_data
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
    entity_type
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
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectAssignee {
      id
      name
      entity_type
    }
    objectParticipant {
      id
      name
      entity_type
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
  context?: readonly (GenericContext | null)[] | null;
  enableReferences?: boolean
  handleClose: () => void
}

interface CaseIncidentEditionFormValues {
  message?: string
  createdBy?: FieldOption
  objectMarking?: FieldOption[]
  objectAssignee?: FieldOption[]
  objectParticipant?: FieldOption[]
  x_opencti_workflow_id: FieldOption
  references: ExternalReferencesValues | undefined
}

const CASE_INCIDENT_TYPE = 'Case-Incident';

const CaseIncidentEditionOverview: FunctionComponent<CaseIncidentEditionOverviewProps> = ({
  caseRef,
  context,
  enableReferences = false,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
  const caseData = useFragment(caseIncidentEditionOverviewFragment, caseRef);

  const { mandatoryAttributes } = useIsMandatoryAttribute(CASE_INCIDENT_TYPE);

  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2),
    severity: Yup.string().nullable(),
    priority: Yup.string().nullable(),
    response_types: Yup.array(),
    description: Yup.string().nullable(),
    x_opencti_workflow_id: Yup.object().nullable(),
    rating: Yup.number().nullable(),
    confidence: Yup.number().nullable(),
    objectAssignee: Yup.array().nullable(),
    objectParticipant: Yup.array().nullable(),
    createdBy: Yup.object().nullable(),
    objectMarking: Yup.array().nullable(),
  }, mandatoryAttributes);
  const validator = useDynamicSchemaEditionValidation(mandatoryAttributes, basicShape);

  const queries = {
    fieldPatch: caseIncidentMutationFieldPatch,
    relationAdd: caseIncidentMutationRelationAdd,
    relationDelete: caseIncidentMutationRelationDelete,
    editionFocus: caseIncidentEditionOverviewFocus,
  };
  const editor = useFormEditor(caseData as GenericData, enableReferences, queries, validator);

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

  const handleSubmitField = (name: string, value: FieldOption | string | string[] | number | number[] | null) => {
    if (!enableReferences) {
      let finalValue: unknown = value as string;
      if (['x_opencti_workflow_id'].includes(name)) {
        finalValue = (value as FieldOption).value;
      }
      validator
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
    createdBy: convertCreatedBy(caseData) as FieldOption,
    objectMarking: convertMarkings(caseData),
    objectAssignee: convertAssignees(caseData),
    objectParticipant: convertParticipants(caseData),
    x_opencti_workflow_id: convertStatus(t_i18n, caseData) as FieldOption,
    references: [],
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues as never}
      validationSchema={validator}
      validateOnChange={true}
      validateOnBlur={true}
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
        <Form>
          <AlertConfidenceForEntity entity={caseData} />
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            required={(mandatoryAttributes.includes('name'))}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={editor.changeField}
            askAi={true}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
          />
          <Field
            component={DateTimePickerField}
            name="created"
            onFocus={editor.changeFocus}
            onSubmit={editor.changeField}
            textFieldProps={{
              label: t_i18n('Incident date'),
              required: (mandatoryAttributes.includes('created')),
              variant: 'standard',
              fullWidth: true,
              helperText: (
                <SubscriptionFocus context={context} fieldName="created" />
              ),
              style: { marginTop: 20 },
            }}
            containerStyle={fieldSpacingContainerStyle}
          />
          <OpenVocabField
            label={t_i18n('Case severity')}
            type="case_severity_ov"
            name="severity"
            required={(mandatoryAttributes.includes('severity'))}
            onSubmit={handleSubmitField}
            onChange={setFieldValue}
            variant="edit"
            containerStyle={fieldSpacingContainerStyle}
            multiple={false}
            editContext={context}
          />
          <OpenVocabField
            label={t_i18n('Case priority')}
            type="case_priority_ov"
            name="priority"
            required={(mandatoryAttributes.includes('priority'))}
            onSubmit={handleSubmitField}
            onChange={setFieldValue}
            variant="edit"
            containerStyle={fieldSpacingContainerStyle}
            multiple={false}
            editContext={context}
          />
          <OpenVocabField
            label={t_i18n('Response type')}
            type="incident_response_types_ov"
            name="response_types"
            required={(mandatoryAttributes.includes('response_types'))}
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
            label={t_i18n('Description')}
            required={(mandatoryAttributes.includes('description'))}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={fieldSpacingContainerStyle}
            onFocus={editor.changeFocus}
            onSubmit={editor.changeField}
            askAi={true}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
            }
          />

          <ObjectAssigneeField
            name="objectAssignee"
            required={(mandatoryAttributes.includes('objectAssignee'))}
            style={fieldSpacingContainerStyle}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectAssignee" />
            }
            onChange={editor.changeAssignee}
          />
          <ObjectParticipantField
            name="objectParticipant"
            required={(mandatoryAttributes.includes('objectParticipant'))}
            style={fieldSpacingContainerStyle}
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
            required={(mandatoryAttributes.includes('createdBy'))}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            helpertext={
              <SubscriptionFocus context={context} fieldName="createdBy" />
            }
            onChange={editor.changeCreated}
          />
          <ObjectMarkingField
            name="objectMarking"
            required={(mandatoryAttributes.includes('objectMarking'))}
            style={fieldSpacingContainerStyle}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectMarking" />
            }
            setFieldValue={setFieldValue}
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
