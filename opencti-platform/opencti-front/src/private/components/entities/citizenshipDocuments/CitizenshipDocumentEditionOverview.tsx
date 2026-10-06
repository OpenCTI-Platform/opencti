import { createFragmentContainer, graphql } from 'react-relay';
import React, { FunctionComponent } from 'react';
import { getCitizenshipDocumentValidator, CITIZENSHIP_DOCUMENT_ENTITY_TYPE } from '@components/entities/citizenshipDocuments/CitizenshipDocumentUtils';
import { FormikConfig } from 'formik/dist/types';
import { Field, Form, Formik } from 'formik';
import OpenVocabField from '@components/common/form/OpenVocabField';
import CreatedByField from '@components/common/form/CreatedByField';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import { ExternalReferencesValues } from '@components/common/form/ExternalReferencesField';
import CommitMessage from '@components/common/form/CommitMessage';
import {
  CitizenshipDocumentEditionOverview_citizenshipDocument$data,
} from '@components/entities/citizenshipDocuments/__generated__/CitizenshipDocumentEditionOverview_citizenshipDocument.graphql';
import {
  CitizenshipDocumentEditionContainer_citizenshipDocument$data,
} from '@components/entities/citizenshipDocuments/__generated__/CitizenshipDocumentEditionContainer_citizenshipDocument.graphql';
import StatusField from '@components/common/form/StatusField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';
import { useIsMandatoryAttribute } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import { adaptFieldValue } from '../../../../utils/String';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';

const citizenshipDocumentMutationFieldPatch = graphql`
  mutation CitizenshipDocumentEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    citizenshipDocumentFieldPatch(
      id: $id
      input: $input
      commitMessage: $commitMessage
      references: $references
    ) {
      ...CitizenshipDocumentEditionOverview_citizenshipDocument
      ...CitizenshipDocument_citizenshipDocument
    }
  }
`;

export const citizenshipDocumentEditionOverviewFocus = graphql`
mutation CitizenshipDocumentEditionOverviewFocusMutation(
  $id: ID!
  $input: EditContext!
) {
  citizenshipDocumentContextPatch(id: $id, input: $input) {
    id
  }
}
`;

const citizenshipDocumentMutationRelationAdd = graphql`
mutation CitizenshipDocumentEditionOverviewRelationAddMutation(
  $id: ID!
  $input: StixRefRelationshipAddInput!
) {
  citizenshipDocumentRelationAdd(id: $id, input: $input) {
    from {
      ...CitizenshipDocumentEditionOverview_citizenshipDocument
    }
  }
}
`;

const citizenshipDocumentMutationRelationDelete = graphql`
mutation CitizenshipDocumentEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
) {
    citizenshipDocumentRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
... CitizenshipDocumentEditionOverview_citizenshipDocument
    }
  }
`;

type CitizenshipDocumentGenericData = CitizenshipDocumentEditionOverview_citizenshipDocument$data & GenericData;

interface CitizenshipDocumentEditionOverviewProps {
  citizenshipDocument: CitizenshipDocumentGenericData;
  enableReferences: boolean;
  context: CitizenshipDocumentEditionContainer_citizenshipDocument$data['editContext'];
  handleClose: () => void;
}

interface CitizenshipDocumentEditionFormData {
  message?: string;
  createdBy?: FieldOption;
  objectMarking?: FieldOption[];
  x_opencti_workflow_id: FieldOption;
  references: ExternalReferencesValues | undefined;
}

const CitizenshipDocumentEditionOverview: FunctionComponent<CitizenshipDocumentEditionOverviewProps> = ({
  citizenshipDocument,
  enableReferences,
  context,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useIsMandatoryAttribute(CITIZENSHIP_DOCUMENT_ENTITY_TYPE);
  const citizenshipDocumentValidator = getCitizenshipDocumentValidator(mandatoryAttributes);

  const queries = {
    fieldPatch: citizenshipDocumentMutationFieldPatch,
    relationAdd: citizenshipDocumentMutationRelationAdd,
    relationDelete: citizenshipDocumentMutationRelationDelete,
    editionFocus: citizenshipDocumentEditionOverviewFocus,
  };
  const editor = useFormEditor(citizenshipDocument, enableReferences, queries, citizenshipDocumentValidator);

  const onSubmit: FormikConfig<CitizenshipDocumentEditionFormData>['onSubmit'] = (values, { setSubmitting }) => {
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
        id: citizenshipDocument.id,
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

  const handleSubmitField = (name: string, value: string | string[] | number | number[] | FieldOption | null) => {
    if (!enableReferences) {
      let finalValue = value;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as FieldOption).value;
      }
      citizenshipDocumentValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: citizenshipDocument.id,
              input: {
                key: name,
                value: finalValue ?? [null],
              },
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = {
    name: citizenshipDocument.name,
    description: citizenshipDocument.description,
    x_opencti_citizenship_document_type: citizenshipDocument.x_opencti_citizenship_document_type,
    x_opencti_workflow_id: convertStatus(t_i18n, citizenshipDocument) as FieldOption,
    createdBy: convertCreatedBy(citizenshipDocument) as FieldOption,
    objectMarking: convertMarkings(citizenshipDocument),
    references: [],
  };

  return (
    <Formik<CitizenshipDocumentEditionFormData>
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={citizenshipDocumentValidator}
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
          <AlertConfidenceForEntity entity={citizenshipDocument} />
          <Field
            component={TextField}
            variant="outlined"
            name="name"
            label={t_i18n('Name')}
            required={(mandatoryAttributes.includes('name'))}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            required={(mandatoryAttributes.includes('description'))}
            uploadEntityId={citizenshipDocument.id}
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
          <OpenVocabField
            label={t_i18n('Citizenship document type')}
            type="citizenship_document_type_ov"
            name="x_opencti_citizenship_document_type"
            required={(mandatoryAttributes.includes('x_opencti_citizenship_document_type'))}
            onChange={setFieldValue}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            multiple={false}
            editContext={context}
            variant="edit"
            containerStyle={fieldSpacingContainerStyle}
          />
          {citizenshipDocument.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="CitizenshipDocument"
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
              id={citizenshipDocument.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default createFragmentContainer(CitizenshipDocumentEditionOverview, {
  citizenshipDocument: graphql`
    fragment CitizenshipDocumentEditionOverview_citizenshipDocument on CitizenshipDocument {
      id
      description
      x_opencti_citizenship_document_type
      standard_id
      entity_type
      x_opencti_stix_ids
      spec_version
      revoked
      x_opencti_reliability
      confidence
      created
      modified
      created_at
      updated_at
      createdBy {
        ... on Identity {
          id
          name
          entity_type
          x_opencti_reliability
        }
      }
      creators {
        id
        name
      }
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
      objectLabel {
        id
        value
        color
      }
      name
      x_opencti_aliases
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
