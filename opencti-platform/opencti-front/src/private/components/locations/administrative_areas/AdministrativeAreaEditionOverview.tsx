import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import ConfidenceField from '@components/common/form/ConfidenceField';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import StatusField from '../../common/form/StatusField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import { useFormatter } from '../../../../components/i18n';
import { AdministrativeAreaEditionOverview_administrativeArea$key } from './__generated__/AdministrativeAreaEditionOverview_administrativeArea.graphql';
import { useDynamicSchemaEditionValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { GenericContext } from '../../common/model/GenericContextModel';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

const administrativeAreaMutationFieldPatch = graphql`
  mutation AdministrativeAreaEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    administrativeAreaFieldPatch(
      id: $id
      input: $input
      commitMessage: $commitMessage
      references: $references
    ) {
      ...AdministrativeAreaEditionOverview_administrativeArea
      ...AdministrativeArea_administrativeArea
    }
  }
`;

export const administrativeAreaEditionOverviewFocus = graphql`
  mutation AdministrativeAreaEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    administrativeAreaContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const administrativeAreaMutationRelationAdd = graphql`
  mutation AdministrativeAreaEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    administrativeAreaRelationAdd(id: $id, input: $input) {
      id
      from {
        ...AdministrativeAreaEditionOverview_administrativeArea
      }
    }
  }
`;

const administrativeAreaMutationRelationDelete = graphql`
  mutation AdministrativeAreaEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    administrativeAreaRelationDelete(
      id: $id
      toId: $toId
      relationship_type: $relationship_type
    ) {
      ...AdministrativeAreaEditionOverview_administrativeArea
    }
  }
`;

export const administrativeAreaEditionOverviewFragment = graphql`
  fragment AdministrativeAreaEditionOverview_administrativeArea on AdministrativeArea {
    id
    name
    description
    latitude
    longitude
    confidence
    entity_type
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
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
`;

const ADMINISTRATIVE_AREA_TYPE = 'Administrative-Area';

interface AdministrativeAreaEditionOverviewProps {
  administrativeAreaRef: AdministrativeAreaEditionOverview_administrativeArea$key;
  context?: readonly (GenericContext | null)[] | null;
  enableReferences?: boolean;
  handleClose: () => void;
}

interface AdministrativeAreaEditionFormValues {
  message?: string;
  references?: FieldOption[];
  createdBy: FieldOption | undefined;
  x_opencti_workflow_id: FieldOption;
  objectMarking?: FieldOption[];
}

const AdministrativeAreaEditionOverview: FunctionComponent<
  AdministrativeAreaEditionOverviewProps
> = ({
  administrativeAreaRef,
  context,
  enableReferences = false,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
  const administrativeArea = useFragment(
    administrativeAreaEditionOverviewFragment,
    administrativeAreaRef,
  );
  const { mandatoryAttributes } = useIsMandatoryAttribute(ADMINISTRATIVE_AREA_TYPE);
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    latitude: Yup.number()
      .typeError(t_i18n('This field must be a number'))
      .nullable(),
    longitude: Yup.number()
      .typeError(t_i18n('This field must be a number'))
      .nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
    createdBy: Yup.object().nullable(),
    objectMarking: Yup.array().nullable(),
  }, mandatoryAttributes);
  const administrativeAreaValidator = useDynamicSchemaEditionValidation(mandatoryAttributes, basicShape);

  const queries = {
    fieldPatch: administrativeAreaMutationFieldPatch,
    relationAdd: administrativeAreaMutationRelationAdd,
    relationDelete: administrativeAreaMutationRelationDelete,
    editionFocus: administrativeAreaEditionOverviewFocus,
  };
  const editor = useFormEditor(
    administrativeArea as GenericData,
    enableReferences,
    queries,
    administrativeAreaValidator,
  );
  const onSubmit: FormikConfig<AdministrativeAreaEditionFormValues>['onSubmit'] = (values, { setSubmitting }) => {
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
        id: administrativeArea.id,
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
  const handleSubmitField = (name: string, value: FieldOption | string | null) => {
    if (!enableReferences) {
      let finalValue: string = value as string;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as FieldOption).value;
      }
      administrativeAreaValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: administrativeArea.id,
              input: [{ key: name, value: [finalValue ?? null] }],
            },
          });
        })
        .catch(() => false);
    }
  };
  const initialValues = {
    name: administrativeArea.name,
    description: administrativeArea.description,
    latitude: administrativeArea.latitude,
    longitude: administrativeArea.longitude,
    confidence: administrativeArea.confidence,
    createdBy: convertCreatedBy(administrativeArea),
    objectMarking: convertMarkings(administrativeArea),
    x_opencti_workflow_id: convertStatus(t_i18n, administrativeArea) as FieldOption,
    references: [],
  };
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues as never}
      validationSchema={administrativeAreaValidator}
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
          <AlertConfidenceForEntity entity={administrativeArea} />
          <Field
            component={TextField}
            variant="standard"
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
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="Administrative-Area"
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            variant="edit"
          />
          <Field
            component={TextField}
            variant="standard"
            style={{ marginTop: 20 }}
            name="latitude"
            type="number"
            label={t_i18n('Latitude')}
            required={(mandatoryAttributes.includes('latitude'))}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={(name: string, value: string) => handleSubmitField(name, (value === '' ? null : value))}
            helperText={
              <SubscriptionFocus context={context} fieldName="latitude" />
            }
          />
          <Field
            component={TextField}
            variant="standard"
            style={{ marginTop: 20 }}
            name="longitude"
            type="number"
            label={t_i18n('Longitude')}
            required={(mandatoryAttributes.includes('longitude'))}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={(name: string, value: string) => handleSubmitField(name, (value === '' ? null : value))}
            helperText={
              <SubscriptionFocus context={context} fieldName="longitude" />
            }
          />
          {administrativeArea.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Administrative-Area"
              onFocus={editor.changeFocus}
              onChange={handleSubmitField}
              setFieldValue={setFieldValue}
              style={{ marginTop: 20 }}
              helpertext={(
                <SubscriptionFocus
                  context={context}
                  fieldName="x_opencti_workflow_id"
                />
              )}
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
              id={administrativeArea.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default AdministrativeAreaEditionOverview;
