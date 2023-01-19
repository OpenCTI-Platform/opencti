import React, { FunctionComponent } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import * as R from 'ramda';
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
import { AdministrativeAreaEditionOverview_administrativeArea$key } from './__generated__/AdministrativeAreaEditionOverview_administrativeArea.graphql';
import { AdministrativeAreaEditionOverviewRelationAddMutation } from './__generated__/AdministrativeAreaEditionOverviewRelationAddMutation.graphql';
import { AdministrativeAreaEditionOverviewFieldPatchMutation } from './__generated__/AdministrativeAreaEditionOverviewFieldPatchMutation.graphql';
import { AdministrativeAreaEditionOverviewFocusMutation } from './__generated__/AdministrativeAreaEditionOverviewFocusMutation.graphql';
import { AdministrativeAreaEditionOverviewRelationDeleteMutation } from './__generated__/AdministrativeAreaEditionOverviewRelationDeleteMutation.graphql';

const administrativeAreaMutationFieldPatch = graphql`
    mutation AdministrativeAreaEditionOverviewFieldPatchMutation(
        $id: ID!
        $input: [EditInput]!
    ) {
        administrativeAreaFieldPatch(id: $id, input: $input){
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

const administrativeAreaValidation = (t: (v: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable().max(5000, t('The value is too long')),
  latitude: Yup.lazy((value) => (value === '' ? Yup.string() : Yup.number().nullable().typeError(t('This field must be a number')))),
  longitude: Yup.lazy((value) => (value === '' ? Yup.string() : Yup.number().nullable().typeError(t('This field must be a number')))),
  x_opencti_workflow_id: Yup.object(),
});

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
const AdministrativeAreaEditionOverview: FunctionComponent<AdministrativeAreaEditionOverviewProps> = ({ administrativeAreaRef, context, enableReferences = false, handleClose }) => {
  const { t } = useFormatter();

  const administrativeArea = useFragment(administrativeAreaEditionOverviewFragment, administrativeAreaRef);

  const createdBy = convertCreatedBy(administrativeArea);
  const objectMarking = convertMarkings(administrativeArea);
  const status = convertStatus(t, administrativeArea);

  const [commitRelationAdd] = useMutation<AdministrativeAreaEditionOverviewRelationAddMutation>(administrativeAreaMutationRelationAdd);
  const [commitRelationDelete] = useMutation<AdministrativeAreaEditionOverviewRelationDeleteMutation>(administrativeAreaMutationRelationDelete);
  const [commitFieldPatch] = useMutation<AdministrativeAreaEditionOverviewFieldPatchMutation>(administrativeAreaMutationFieldPatch);
  const [commitEditionFocus] = useMutation<AdministrativeAreaEditionOverviewFocusMutation>(administrativeAreaEditionOverviewFocus);

  const handleChangeCreatedBy = (_: string, value: Option) => {
    if (!enableReferences) {
      commitFieldPatch({
        variables: {
          id: administrativeArea.id,
          input: [{ key: 'createdBy', value: [value.value] }],
        },
      });
    }
  };
  const handleChangeObjectMarking = (_: string, values: Option[]) => {
    if (!enableReferences) {
      const currentMarkingDefinitions = (administrativeArea.objectMarking?.edges ?? []).map(({ node }) => ({ label: node.definition, value: node.id }));
      const added = R.difference(values, currentMarkingDefinitions).at(0);
      const removed = R.difference(currentMarkingDefinitions, values).at(0);
      if (added) {
        commitRelationAdd({
          variables: {
            id: administrativeArea.id,
            input: {
              toId: added.value,
              relationship_type: 'object-marking',
            },
          },
        });
      }
      if (removed) {
        commitRelationDelete({
          variables: {
            id: administrativeArea.id,
            toId: removed.value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  };

  const handleSubmitField = (name: string, value: Option | string) => {
    if (!enableReferences) {
      let finalValue: string = value as string;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as Option).value;
      }
      administrativeAreaValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitFieldPatch({
            variables: {
              id: administrativeArea.id,
              input: [{ key: name, value: [finalValue ?? ''] }],
            },
          });
        })
        .catch(() => false);
    }
  };

  const handleChangeFocus = (name: string) => {
    commitEditionFocus({
      variables: {
        id: administrativeArea.id,
        input: {
          focusOn: name,
        },
      },
    });
  };

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

    commitFieldPatch({
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

  const initialValues = {
    name: administrativeArea.name,
    description: administrativeArea.description,
    latitude: administrativeArea.latitude,
    longitude: administrativeArea.longitude,
    x_opencti_workflow_id: status,
    createdBy,
    objectMarking,
    status,
  };

  return (
        <Formik
            enableReinitialize={true}
            initialValues={initialValues as never}
            validationSchema={administrativeAreaValidation(t)}
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
                    <Field
                        component={TextField}
                        variant="standard"
                        style={{ marginTop: 20 }}
                        name="latitude"
                        label={t('Latitude')}
                        fullWidth={true}
                        onFocus={handleChangeFocus}
                        onSubmit={handleSubmitField}
                        helperText={
                            <SubscriptionFocus context={context} fieldName="latitude" />
                        }
                    />
                    <Field
                        component={TextField}
                        variant="standard"
                        style={{ marginTop: 20 }}
                        name="longitude"
                        label={t('Longitude')}
                        fullWidth={true}
                        onFocus={handleChangeFocus}
                        onSubmit={handleSubmitField}
                        helperText={
                            <SubscriptionFocus context={context} fieldName="longitude" />
                        }
                    />
                    {administrativeArea?.workflowEnabled && (
                        <StatusField
                            name="x_opencti_workflow_id"
                            type="AdministrativeArea"
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
                        style={{ marginTop: 20, width: '100%' }}
                        setFieldValue={setFieldValue}
                        helpertext={
                            <SubscriptionFocus context={context} fieldName="createdBy" />
                        }
                        onChange={handleChangeCreatedBy}
                    />
                    <ObjectMarkingField
                        name="objectMarking"
                        style={{ marginTop: 20, width: '100%' }}
                        helpertext={
                            <SubscriptionFocus
                                context={context}
                                fieldname="objectMarking"
                            />
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
                            id={administrativeArea.id}
                        />
                    )}
                </Form>
            )}
        </Formik>
  );
};

export default AdministrativeAreaEditionOverview;
