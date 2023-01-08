import React, { FunctionComponent } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
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
import { DataComponentEditionOverview_dataComponent$key } from './__generated__/DataComponentEditionOverview_dataComponent.graphql';
import StatusField from '../../common/form/StatusField';
import CommitMessage from '../../common/form/CommitMessage';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';
import { DataComponentEditionOverviewRelationAddMutation } from './__generated__/DataComponentEditionOverviewRelationAddMutation.graphql';
import { DataComponentEditionOverviewRelationDeleteMutation } from './__generated__/DataComponentEditionOverviewRelationDeleteMutation.graphql';
import { DataComponentEditionOverviewFieldPatchMutation } from './__generated__/DataComponentEditionOverviewFieldPatchMutation.graphql';
import { DataComponentEditionOverviewFocusMutation } from './__generated__/DataComponentEditionOverviewFocusMutation.graphql';
import { Option } from '../../common/form/ReferenceField';
import { adaptFieldValue } from '../../../../utils/String';

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

const dataComponentValidation = (t: (message: string) => string) => Yup.object()
  .shape({
    name: Yup.string()
      .required(t('This field is required')),
    description: Yup.string()
      .min(3, t('The value is too short'))
      .max(5000, t('The value is too long'))
      .required(t('This field is required')),
    references: Yup.array()
      .required(t('This field is required')),
    x_opencti_workflow_id: Yup.object(),
    confidence: Yup.number(),
  });

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
  name: string,
  description: string | null,
  createdBy: Option | undefined,
  objectMarking: Option[],
  x_opencti_workflow_id: string | { label: string, color: string, value: string, order: string },
  confidence: number | null,
  message?: string
  references?: Option[]
}

const DataComponentEditionOverview: FunctionComponent<DataComponentEditionOverviewComponentProps> = ({
  data,
  context,
  enableReferences,
  handleClose,
}) => {
  const { t } = useFormatter();

  const dataComponent = useFragment(DataComponentEditionOverviewFragment, data);

  const [commitRelationAdd] = useMutation<DataComponentEditionOverviewRelationAddMutation>(dataComponentMutationRelationAdd);
  const [commitRelationDelete] = useMutation<DataComponentEditionOverviewRelationDeleteMutation>(dataComponentMutationRelationDelete);
  const [commitFieldPatch] = useMutation<DataComponentEditionOverviewFieldPatchMutation>(dataComponentMutationFieldPatch);
  const [commitEditionFocus] = useMutation<DataComponentEditionOverviewFocusMutation>(dataComponentEditionOverviewFocus);

  const handleChangeFocus = (name: string) => {
    commitEditionFocus({
      variables: {
        id: dataComponent.id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  const handleSubmitField = (name: string, value: string | { label: string, color: string, value: string, order: string }) => {
    if (!enableReferences) {
      let finalValue: string;
      if (name === 'x_opencti_workflow_id' && typeof value !== 'string') {
        finalValue = value.value;
      } else {
        finalValue = value as string;
      }
      dataComponentValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitFieldPatch({
            variables: {
              id: dataComponent.id,
              input: [{
                key: name,
                value: [finalValue ?? ''],
              }],
            },
          });
        })
        .catch(() => false);
    }
  };

  const handleChangeCreatedBy = (name: string, value: Option) => {
    if (!enableReferences) {
      commitFieldPatch({
        variables: {
          id: dataComponent.id,
          input: [{
            key: 'createdBy',
            value: [value.value],
          }],
        },
      });
    }
  };

  const handleChangeObjectMarking = (name: string, values: Option[]) => {
    if (!enableReferences) {
      const currentMarkings = (dataComponent?.objectMarking?.edges ?? []).map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      }));
      const added = values.filter((v) => !currentMarkings.map((c) => c.value).includes(v.value));
      const removed = currentMarkings.filter((c) => !values.map((v) => v.value).includes(c.value));
      if (added.length > 0) {
        commitRelationAdd({
          variables: {
            id: dataComponent.id,
            input: {
              toId: added[0].value,
              relationship_type: 'object-marking',
            },
          },
        });
      }
      if (removed.length > 0) {
        commitRelationDelete({
          variables: {
            id: dataComponent.id,
            toId: removed[0].value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  };

  const onSubmit: FormikConfig<DataComponentAddInput>['onSubmit'] = (values, { setSubmitting }) => {
    const {
      message,
      references,
      ...otherValues
    } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);

    const inputValues = Object.entries({
      ...otherValues,
      createdBy: values.createdBy?.value,
      objectMarking: (values.objectMarking ?? []).map(({ value }) => value),
    }).map(([key, value]) => ({
      key,
      value: adaptFieldValue(value),
    }));

    commitFieldPatch({
      variables: {
        id: dataComponent.id,
        input: inputValues,
        commitMessage: commitMessage.length > 0 ? commitMessage : null,
        references: commitReferences,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const initialValues: DataComponentAddInput = {
    name: dataComponent.name,
    description: dataComponent.description,
    createdBy: convertCreatedBy(dataComponent),
    objectMarking: convertMarkings(dataComponent),
    x_opencti_workflow_id: convertStatus(t, dataComponent),
    confidence: dataComponent.confidence,
  };
  return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={dataComponentValidation(t)}
        onSubmit={onSubmit}
      >
        {({
          submitForm,
          isSubmitting,
          validateForm,
          setFieldValue,
          values,
        }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t('Name')}
              fullWidth={true}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="name" />
              }
            />
            <ConfidenceField
              name="confidence"
              onFocus={handleChangeFocus}
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
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="description" />
              }
            />
            {dataComponent.workflowEnabled && (
              <StatusField
                name="x_opencti_workflow_id"
                type="Data-Component"
                onFocus={handleChangeFocus}
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
              style={{
                marginTop: 20,
                width: '100%',
              }}
              setFieldValue={setFieldValue}
              helpertext={
                <SubscriptionFocus context={context} fieldName="createdBy" />
              }
              onChange={handleChangeCreatedBy}
            />
            <ObjectMarkingField
              name="objectMarking"
              style={{
                marginTop: 20,
                width: '100%',
              }}
              helpertext={
                <SubscriptionFocus context={context} fieldname="objectMarking" />
              }
              onChange={handleChangeObjectMarking}
            />
            {enableReferences && (
              <CommitMessage
                submitForm={submitForm}
                disabled={isSubmitting}
                validateForm={validateForm}
                setFieldValue={setFieldValue}
                values={values}
                id={dataComponent.id}
              />
            )}
          </Form>
        )}
      </Formik>
  );
};
export default DataComponentEditionOverview;
