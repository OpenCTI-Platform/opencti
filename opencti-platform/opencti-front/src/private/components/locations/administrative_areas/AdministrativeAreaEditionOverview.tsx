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
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import StatusField from '../../common/form/StatusField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import { useFormatter } from '../../../../components/i18n';
import { Option } from '../../common/form/ReferenceField';
import {
  AdministrativeAreaEditionOverview_administrativeArea$key,
} from './__generated__/AdministrativeAreaEditionOverview_administrativeArea.graphql';
import { useYupSchemaBuilder } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';

const administrativeAreaMutationFieldPatch = graphql`
    mutation AdministrativeAreaEditionOverviewFieldPatchMutation(
        $id: ID!
        $input: [EditInput]!
        $commitMessage: String
        $references: [String]
    ) {
        administrativeAreaFieldPatch(id: $id, input: $input, commitMessage: $commitMessage, references: $references){
            ...AdministrativeAreaEditionOverview_administrativeArea
            ...AdministrativeArea_administrativeArea
        }

    }
`;

export const administrativeAreaEditionOverviewFocus = graphql`
    mutation AdministrativeAreaEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
        administrativeAreaContextPatch(id: $id,  input: $input) {
            id
        }
    }
`;

const administrativeAreaMutationRelationAdd = graphql`
    mutation AdministrativeAreaEditionOverviewRelationAddMutation(
        $id: ID!
        $input: StixMetaRelationshipAddInput!
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
        administrativeAreaRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
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

interface AdministrativeAreaEditionOverviewProps {
  administrativeAreaRef: AdministrativeAreaEditionOverview_administrativeArea$key,
  context: readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[] | null
  enableReferences?: boolean
  handleClose: () => void
}

interface AdministrativeAreaEditionFormValues {
  message?: string
  references?: Option[]
  createdBy?: Option
  x_opencti_workflow_id: Option
  objectMarking?: Option[]
}

// eslint-disable-next-line max-len
const AdministrativeAreaEditionOverview: FunctionComponent<AdministrativeAreaEditionOverviewProps> = ({
  administrativeAreaRef,
  context,
  enableReferences = false,
  handleClose,
}) => {
  const { t } = useFormatter();
  const administrativeArea = useFragment(administrativeAreaEditionOverviewFragment, administrativeAreaRef);

  const basicShape = {
    name: Yup.string().required(t('This field is required')),
    description: Yup.string().nullable(),
    latitude: Yup.number().typeError(t('This field must be a number')).nullable(),
    longitude: Yup.number().typeError(t('This field must be a number')).nullable(),
    references: Yup.array().nullable(),
    x_opencti_workflow_id: Yup.object().nullable(),
  };
  const administrativeAreaValidator = useYupSchemaBuilder('Administrative-Area', basicShape);

  const queries = {
    fieldPatch: administrativeAreaMutationFieldPatch,
    relationAdd: administrativeAreaMutationRelationAdd,
    relationDelete: administrativeAreaMutationRelationDelete,
    editionFocus: administrativeAreaEditionOverviewFocus,
  };
  const editor = useFormEditor(administrativeArea, enableReferences, queries, administrativeAreaValidator);

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
        commitMessage: commitMessage.length > 0 ? commitMessage : null,
        references: commitReferences,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleSubmitField = (name: string, value: Option | string) => {
    if (!enableReferences) {
      let finalValue: string = value as string;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as Option).value;
      }
      administrativeAreaValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: administrativeArea.id,
              input: [{ key: name, value: [finalValue ?? ''] }],
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
    createdBy: convertCreatedBy(administrativeArea),
    objectMarking: convertMarkings(administrativeArea),
    x_opencti_workflow_id: convertStatus(t, administrativeArea) as Option,
    references: [],
  };
  return (
        <Formik enableReinitialize={true}
                initialValues={initialValues as never}
                validationSchema={administrativeAreaValidator}
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
                        helperText={<SubscriptionFocus context={context} fieldName="name"/>}
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
                        helperText={<SubscriptionFocus context={context} fieldName="description"/>}
                    />
                    <Field
                        component={TextField}
                        variant="standard"
                        style={{ marginTop: 20 }}
                        name="latitude"
                        label={t('Latitude')}
                        fullWidth={true}
                        onFocus={editor.changeFocus}
                        onSubmit={handleSubmitField}
                        helperText={<SubscriptionFocus context={context} fieldName="latitude"/>}
                    />
                    <Field
                        component={TextField}
                        variant="standard"
                        style={{ marginTop: 20 }}
                        name="longitude"
                        label={t('Longitude')}
                        fullWidth={true}
                        onFocus={editor.changeFocus}
                        onSubmit={handleSubmitField}
                        helperText={<SubscriptionFocus context={context} fieldName="longitude"/>}
                    />
                    {administrativeArea?.workflowEnabled && (
                        <StatusField
                            name="x_opencti_workflow_id"
                            type="Administrative-Area"
                            onFocus={editor.changeFocus}
                            onChange={handleSubmitField}
                            setFieldValue={setFieldValue}
                            style={{ marginTop: 20 }}
                            helpertext={<SubscriptionFocus context={context} fieldName="x_opencti_workflow_id"/>}
                        />
                    )}
                    <CreatedByField
                        name="createdBy"
                        style={{ marginTop: 20, width: '100%' }}
                        setFieldValue={setFieldValue}
                        helpertext={<SubscriptionFocus context={context} fieldName="createdBy"/>}
                        onChange={editor.changeCreated}
                    />
                    <ObjectMarkingField
                        name="objectMarking"
                        style={{ marginTop: 20, width: '100%' }}
                        helpertext={<SubscriptionFocus context={context} fieldname="objectMarking"/>}
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
