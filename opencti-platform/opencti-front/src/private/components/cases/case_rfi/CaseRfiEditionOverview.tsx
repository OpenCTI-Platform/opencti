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
import { CaseRfiEditionOverview_case$key } from './__generated__/CaseRfiEditionOverview_case.graphql';

export const caseRfiMutationFieldPatch = graphql`
  mutation CaseRfiEditionOverviewCaseFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    caseRfiFieldPatch(
      id: $id
      input: $input
      commitMessage: $commitMessage
      references: $references
    ) {
      ...CaseRfiEditionOverview_case
      ...CaseRfi_case
    }
  }
`;

export const caseRfiEditionOverviewFocus = graphql`
  mutation CaseRfiEditionOverviewCaseFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    caseRfiContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const caseRfiEditionOverviewFragment = graphql`
  fragment CaseRfiEditionOverview_case on CaseRfi {
    id
    name
    revoked
    description
    confidence
    created
    information_types
    severity
    priority
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

const caseRfiMutationRelationAdd = graphql`
  mutation CaseRfiEditionOverviewCaseRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    caseRfiRelationAdd(id: $id, input: $input) {
      from {
        ...CaseRfiEditionOverview_case
      }
    }
  }
`;

const caseRfiMutationRelationDelete = graphql`
  mutation CaseRfiEditionOverviewCaseRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    caseRfiRelationDelete(
      id: $id
      toId: $toId
      relationship_type: $relationship_type
    ) {
      ...CaseRfiEditionOverview_case
    }
  }
`;

interface CaseRfiEditionOverviewProps {
  caseRef: CaseRfiEditionOverview_case$key;
  context:
  | readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[]
  | null;
  enableReferences?: boolean;
  handleClose: () => void;
}

interface CaseRfiEditionFormValues {
  message?: string
  createdBy?: Option
  objectMarking?: Option[]
  objectAssignee?: Option[]
  x_opencti_workflow_id: Option
  references: ExternalReferencesValues | undefined
}

const CaseRfiEditionOverviewComponent: FunctionComponent<
CaseRfiEditionOverviewProps
> = ({ caseRef, context, enableReferences = false, handleClose }) => {
  const { t } = useFormatter();
  const caseData = useFragment(caseRfiEditionOverviewFragment, caseRef);

  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
    information_types: Yup.array().nullable(),
    severity: Yup.string().nullable(),
    priority: Yup.string().nullable(),
    x_opencti_workflow_id: Yup.object().nullable(),
    rating: Yup.number().nullable(),
    confidence: Yup.number().nullable(),
  };
  const caseValidator = useSchemaEditionValidation('Case-Rfi', basicShape);

  const queries = {
    fieldPatch: caseRfiMutationFieldPatch,
    relationAdd: caseRfiMutationRelationAdd,
    relationDelete: caseRfiMutationRelationDelete,
    editionFocus: caseRfiEditionOverviewFocus,
  };
  const editor = useFormEditor(caseData, enableReferences, queries, caseValidator);

  const onSubmit: FormikConfig<CaseRfiEditionFormValues>['onSubmit'] = (values, { setSubmitting }) => {
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
      caseValidator
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
    created: caseData.created,
    confidence: caseData.confidence,
    information_types: caseData.information_types,
    severity: caseData.severity,
    priority: caseData.priority,
    createdBy: convertCreatedBy(caseData) as Option,
    objectMarking: convertMarkings(caseData),
    objectAssignee: convertAssignees(caseData),
    x_opencti_workflow_id: convertStatus(t, caseData) as Option,
    references: [],
  };
  return (
    <Formik enableReinitialize={true} initialValues={initialValues as never}
            validationSchema={caseValidator}
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
            style={{ marginBottom: '20px' }}
          />
          <Field
            component={DateTimePickerField}
            name="created"
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            TextFieldProps={{
              label: t('Request for Information date'),
              variant: 'standard',
              fullWidth: true,
              helperText: (
                <SubscriptionFocus context={context} fieldName="created" />
              ),
            }}
          />
          <OpenVocabField
            label={t('Information type')}
            type="request_for_information_types_ov"
            name="information_types"
            onSubmit={handleSubmitField}
            onChange={(name, value) => setFieldValue(name, value)}
            variant="edit"
            containerStyle={fieldSpacingContainerStyle}
            multiple={true}
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
          <OpenVocabField
            label={t('Case priority')}
            type="case_priority_ov"
            name="priority"
            onSubmit={handleSubmitField}
            onChange={(name, value) => setFieldValue(name, value)}
            variant="edit"
            containerStyle={fieldSpacingContainerStyle}
            multiple={false}
            editContext={context}
          />
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="Case-Rfi"
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
              type="Case-Rfi"
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

export default CaseRfiEditionOverviewComponent;
