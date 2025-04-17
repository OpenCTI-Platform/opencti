import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import { useFormatter } from '../../../../components/i18n';
import { DataComponentEditionOverview_dataComponent$key } from './__generated__/DataComponentEditionOverview_dataComponent.graphql';
import StatusField from '../../common/form/StatusField';
import CommitMessage from '../../common/form/CommitMessage';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { adaptFieldValue } from '../../../../utils/String';
import { useDynamicSchemaEditionValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';
import DataComponentDeletion from './DataComponentDeletion';

const dataComponentMutationFieldPatch = graphql`
  mutation DataComponentEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    dataComponentFieldPatch(
      id: $id
      input: $input
      commitMessage: $commitMessage
      references: $references
    ) {
      ...DataComponentEditionOverview_dataComponent
      ...DataComponent_dataComponent
    }
  }
`;

export const dataComponentEditionOverviewFocus = graphql`
  mutation DataComponentEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    dataComponentContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const dataComponentMutationRelationAdd = graphql`
  mutation DataComponentEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    dataComponentRelationAdd(id: $id, input: $input) {
      from {
        ...DataComponentEditionOverview_dataComponent
      }
    }
  }
`;

const dataComponentMutationRelationDelete = graphql`
  mutation DataComponentEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    dataComponentRelationDelete(
      id: $id
      toId: $toId
      relationship_type: $relationship_type
    ) {
      ...DataComponentEditionOverview_dataComponent
    }
  }
`;

const DataComponentEditionOverviewFragment = graphql`
  fragment DataComponentEditionOverview_dataComponent on DataComponent {
    id
    name
    confidence
    entity_type
    description
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

const DATA_COMPONENT_TYPE = 'Data-Component';

interface DataComponentEditionOverviewComponentProps {
  data: DataComponentEditionOverview_dataComponent$key;
  context:
  | readonly ({
    readonly focusOn: string | null | undefined;
    readonly name: string;
  } | null)[]
  | null | undefined;
  enableReferences?: boolean;
  handleClose: () => void;
}

interface DataComponentAddInput {
  name: string
  description: string | null
  createdBy: FieldOption | undefined
  objectMarking: FieldOption[]
  x_opencti_workflow_id: FieldOption
  confidence: number | undefined
  message?: string
  references?: FieldOption[]
}

const DataComponentEditionOverview: FunctionComponent<
DataComponentEditionOverviewComponentProps
> = ({ data, context, enableReferences = false, handleClose }) => {
  const { t_i18n } = useFormatter();
  const dataComponent = useFragment(DataComponentEditionOverviewFragment, data);

  const { mandatoryAttributes } = useIsMandatoryAttribute(DATA_COMPONENT_TYPE);
  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
    createdBy: Yup.object().nullable(),
    objectMarking: Yup.array().nullable(),
  }, mandatoryAttributes);
  const dataComponentValidator = useDynamicSchemaEditionValidation(
    mandatoryAttributes,
    basicShape,
    ['objects'],
  );

  const queries = {
    fieldPatch: dataComponentMutationFieldPatch,
    relationAdd: dataComponentMutationRelationAdd,
    relationDelete: dataComponentMutationRelationDelete,
    editionFocus: dataComponentEditionOverviewFocus,
  };
  const editor = useFormEditor(
    dataComponent as GenericData,
    enableReferences,
    queries,
    dataComponentValidator,
  );

  const onSubmit: FormikConfig<DataComponentAddInput>['onSubmit'] = (values, { setSubmitting }) => {
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
        id: dataComponent.id,
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

  const handleSubmitField = (
    name: string,
    value: string | FieldOption | number | number[] | null,
  ) => {
    if (!enableReferences) {
      let finalValue: unknown = value as string;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as FieldOption).value;
      }
      dataComponentValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: dataComponent.id,
              input: [{ key: name, value: finalValue || '' }],
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues: DataComponentAddInput = {
    name: dataComponent.name,
    description: dataComponent.description ?? '',
    createdBy: convertCreatedBy(dataComponent) as FieldOption,
    objectMarking: convertMarkings(dataComponent),
    x_opencti_workflow_id: convertStatus(t_i18n, dataComponent) as FieldOption,
    confidence: dataComponent.confidence ?? undefined,
    references: [],
  };
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={dataComponentValidator}
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
          <AlertConfidenceForEntity entity={dataComponent} />
          <Field
            component={TextField}
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
          <ConfidenceField
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            entityType="Data-Component"
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
            style={{ marginTop: 20 }}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
            }
          />
          {dataComponent.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              required={(mandatoryAttributes.includes('x_opencti_workflow_id'))}
              type="Data-Component"
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
          <div style={{ display: 'flex', justifyContent: 'space-between', flex: 1 }}>
            <DataComponentDeletion
              id={dataComponent.id}
            />
            {enableReferences && (
              <CommitMessage
                submitForm={submitForm}
                disabled={isSubmitting || !isValid || !dirty}
                setFieldValue={setFieldValue}
                open={false}
                values={values.references}
                id={dataComponent.id}
              />
            )}
          </div>
        </Form>
      )}
    </Formik>
  );
};
export default DataComponentEditionOverview;
