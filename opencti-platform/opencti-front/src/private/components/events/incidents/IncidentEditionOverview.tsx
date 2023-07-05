import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/MarkdownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import StatusField from '../../common/form/StatusField';
import {
  convertAssignees,
  convertCreatedBy,
  convertMarkings, convertParticipants,
  convertStatus,
} from '../../../../utils/edition';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import { Option } from '../../common/form/ReferenceField';
import { IncidentEditionOverview_incident$key } from './__generated__/IncidentEditionOverview_incident.graphql';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import ObjectParticipantField from '../../common/form/ObjectParticipantField';

const incidentMutationFieldPatch = graphql`
  mutation IncidentEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    incidentEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...IncidentEditionOverview_incident
        ...Incident_incident
      }
    }
  }
`;

export const incidentEditionOverviewFocus = graphql`
  mutation IncidentEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    incidentEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const incidentMutationRelationAdd = graphql`
  mutation IncidentEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    incidentEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...IncidentEditionOverview_incident
        }
      }
    }
  }
`;

const incidentMutationRelationDelete = graphql`
  mutation IncidentEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    incidentEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...IncidentEditionOverview_incident
      }
    }
  }
`;

const incidentEditionOverviewFragment = graphql`
  fragment IncidentEditionOverview_incident on Incident {
    id
    name
    confidence
    description
    source
    incident_type
    severity
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
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
    is_inferred
  }
`;

interface IncidentEditionOverviewProps {
  incidentRef: IncidentEditionOverview_incident$key;
  context:
  | readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[]
  | null;
  enableReferences?: boolean;
  handleClose: () => void;
}

interface IncidentEditionFormValues {
  message?: string;
  references?: Option[];
  createdBy: Option | undefined;
  x_opencti_workflow_id: Option;
  objectMarking?: Option[];
  objectAssignee?: Option[];
  objectParticipant?: Option[];

}

const IncidentEditionOverviewComponent: FunctionComponent<
IncidentEditionOverviewProps
> = ({ incidentRef, context, enableReferences = false, handleClose }) => {
  const { t } = useFormatter();
  const incident = useFragment(incidentEditionOverviewFragment, incidentRef);
  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    incident_type: Yup.string().nullable(),
    severity: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    description: Yup.string().nullable(),
    x_opencti_workflow_id: Yup.object(),
    references: Yup.array(),
  };
  const incidentValidator = useSchemaEditionValidation('Incident', basicShape);
  const queries = {
    fieldPatch: incidentMutationFieldPatch,
    relationAdd: incidentMutationRelationAdd,
    relationDelete: incidentMutationRelationDelete,
    editionFocus: incidentEditionOverviewFocus,
  };
  const editor = useFormEditor(
    incident,
    enableReferences,
    queries,
    incidentValidator,
  );
  const onSubmit: FormikConfig<IncidentEditionFormValues>['onSubmit'] = (
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
      objectAssignee: (values.objectAssignee ?? []).map(({ value }) => value),
      objectParticipant: (values.objectParticipant ?? []).map(({ value }) => value),
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));
    editor.fieldPatch({
      variables: {
        id: incident.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references: commitReferences,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };
  const handleSubmitField = (name: string, value: string | string[] | number | number[] | null) => {
    if (!enableReferences) {
      let finalValue: string = value as string;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as unknown as Option).value;
      }
      incidentValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: incident.id,
              input: [{ key: name, value: [finalValue ?? ''] }],
            },
          });
        })
        .catch(() => false);
    }
  };
  const isInferred = incident.is_inferred;
  const initialValues = {
    name: incident.name,
    description: incident.description,
    incident_type: incident.incident_type,
    severity: incident.severity,
    createdBy: convertCreatedBy(incident) as Option,
    objectMarking: convertMarkings(incident),
    objectAssignee: convertAssignees(incident),
    objectParticipant: convertParticipants(incident),
    x_opencti_workflow_id: convertStatus(t, incident) as Option,
    confidence: incident.confidence,
    references: [],
  };
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={incidentValidator}
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
            disabled={isInferred}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
          />
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="Incident"
            disabled={isInferred}
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          <OpenVocabField
            label={t('Incident type')}
            type="incident-type-ov"
            name="incident_type"
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            onChange={setFieldValue}
            containerStyle={fieldSpacingContainerStyle}
            variant="edit"
            multiple={false}
            editContext={context}
          />
          <OpenVocabField
            label={t('Severity')}
            type="incident-severity-ov"
            name="severity"
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            onChange={setFieldValue}
            containerStyle={fieldSpacingContainerStyle}
            variant="edit"
            multiple={false}
            editContext={context}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t('Description')}
            fullWidth={true}
            multiline={true}
            disabled={isInferred}
            rows="4"
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
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
          {incident?.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Incident"
              onFocus={editor.changeFocus}
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
            disabled={isInferred}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectMarking" />
            }
            onChange={editor.changeMarking}
          />
          {enableReferences && (
            <CommitMessage
              submitForm={submitForm}
              disabled={isSubmitting || !isValid || !dirty}
              open={false}
              values={values.references}
              setFieldValue={setFieldValue}
              id={incident.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default IncidentEditionOverviewComponent;
