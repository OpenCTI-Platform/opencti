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
import TextField from '../../../../components/TextField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import MarkDownField from '../../../../components/MarkDownField';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import CommitMessage from '../../common/form/CommitMessage';
import { ExternalReferencesValues } from '../../common/form/ExternalReferencesField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { CaseIncidentEditionOverview_case$key } from './__generated__/CaseIncidentEditionOverview_case.graphql';

export const caseIncidentMutationFieldPatch = graphql`
  mutation CaseIncidentEditionOverviewCaseFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    caseIncidentFieldPatch(
      id: $id
      input: $input
      commitMessage: $commitMessage
      references: $references
    ) {
      ...CaseIncidentEditionOverview_case
      ...CaseIncident_case
    }
  }
`;

export const caseIncidentEditionOverviewFocus = graphql`
  mutation CaseIncidentEditionOverviewCaseFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    caseIncidentContextPatch(id: $id, input: $input) {
      id
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
  }
`;

const caseIncidentMutationRelationAdd = graphql`
  mutation CaseIncidentEditionOverviewCaseRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    caseRelationAdd(id: $id, input: $input) {
      from {
        ...CaseIncidentEditionOverview_case
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
    caseRelationDelete(
      id: $id
      toId: $toId
      relationship_type: $relationship_type
    ) {
      ...CaseIncidentEditionOverview_case
    }
  }
`;

interface CaseIncidentEditionOverviewProps {
  caseRef: CaseIncidentEditionOverview_case$key;
  context:
  | readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[]
  | null;
  enableReferences?: boolean;
  handleClose: () => void;
}

interface CaseIncidentEditionFormValues {
  message?: string
  createdBy?: Option
  objectMarking?: Option[]
  objectAssignee?: Option[]
  x_opencti_workflow_id: Option
  references: ExternalReferencesValues | undefined
}

const CaseIncidentEditionOverviewComponent: FunctionComponent<
CaseIncidentEditionOverviewProps
> = ({ caseRef, context, enableReferences = false, handleClose }) => {
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
      if (name === 'x_opencti_workflow_id') {
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
    x_opencti_workflow_id: convertStatus(t, caseData) as Option,
    references: [],
  };
  return (
    <Formik enableReinitialize={true} initialValues={initialValues as never}
      validationSchema={caseIncidentValidator}
      onSubmit={onSubmit}>
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
          <Field
            component={DateTimePickerField}
            name="created"
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            TextFieldProps={{
              label: t('Incident date'),
              variant: 'standard',
              fullWidth: true,
              helperText: (
                <SubscriptionFocus context={context} fieldName="created" />
              ),
            }}
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
            onSubmit={handleSubmitField}
            entityType="Case-Incident"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
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
              type="Case-Incident"
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
                  id={caseData.id}
              />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default CaseIncidentEditionOverviewComponent;
