import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import { useFormatter } from '../../../../components/i18n';
import {
  DataComponentEditionOverview_dataComponent$key,
} from './__generated__/DataComponentEditionOverview_dataComponent.graphql';
import StatusField from '../../common/form/StatusField';
import CommitMessage from '../../common/form/CommitMessage';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { Option } from '../../common/form/ReferenceField';
import { adaptFieldValue } from '../../../../utils/String';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';

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
  mutation DataComponentEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    dataComponentContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const dataComponentMutationRelationAdd = graphql`
  mutation DataComponentEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput!
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
    description
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

interface DataComponentEditionOverviewComponentProps {
  data: DataComponentEditionOverview_dataComponent$key
  context: readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[] | null
  enableReferences?: boolean
  handleClose: () => void
}

interface DataComponentAddInput {
  name: string
  description: string | null
  createdBy: Option | undefined
  objectMarking: Option[]
  x_opencti_workflow_id: Option
  confidence: number | null
  message?: string
  references?: Option[]
}

const DataComponentEditionOverview: FunctionComponent<DataComponentEditionOverviewComponentProps> = ({
  data,
  context,
  enableReferences = false,
  handleClose,
}) => {
  const { t } = useFormatter();

  const dataComponent = useFragment(DataComponentEditionOverviewFragment, data);

  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
    confidence: Yup.number().nullable(),
    references: Yup.array(),
    x_opencti_workflow_id: Yup.object(),
  };
  const dataComponentValidator = useSchemaEditionValidation('Data-Component', basicShape);

  const queries = {
    fieldPatch: dataComponentMutationFieldPatch,
    relationAdd: dataComponentMutationRelationAdd,
    relationDelete: dataComponentMutationRelationDelete,
    editionFocus: dataComponentEditionOverviewFocus,
  };
  const editor = useFormEditor(dataComponent, enableReferences, queries, dataComponentValidator);

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
    value: string | Option | null,
  ) => {
    if (!enableReferences) {
      let finalValue: unknown = value as string;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as Option).value;
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
    description: dataComponent.description,
    createdBy: convertCreatedBy(dataComponent) as Option,
    objectMarking: convertMarkings(dataComponent),
    x_opencti_workflow_id: convertStatus(t, dataComponent) as Option,
    confidence: dataComponent.confidence,
    references: [],
  };
  return (
    <Formik enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={dataComponentValidator}
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
          <ConfidenceField
            name="confidence"
            onFocus={editor.changeFocus}
            onChange={handleSubmitField}
            label={t('Confidence')}
            fullWidth={true}
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
            style={{ marginTop: 20, width: '100%' }}
            setFieldValue={setFieldValue}
            helpertext={
              <SubscriptionFocus context={context} fieldName="createdBy" />
            }
            onChange={editor.changeCreated}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={{ marginTop: 20, width: '100%' }}
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
              id={dataComponent.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};
export default DataComponentEditionOverview;
