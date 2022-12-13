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
import { CityEditionOverview_city$key } from './__generated__/CityEditionOverview_city.graphql';
import { CityEditionOverviewRelationAddMutation } from './__generated__/CityEditionOverviewRelationAddMutation.graphql';
import { CityEditionOverviewFieldPatchMutation } from './__generated__/CityEditionOverviewFieldPatchMutation.graphql';
import { CityEditionOverviewFocusMutation } from './__generated__/CityEditionOverviewFocusMutation.graphql';
import { CityEditionOverviewRelationDeleteMutation } from './__generated__/CityEditionOverviewRelationDeleteMutation.graphql';

const cityMutationFieldPatch = graphql`
  mutation CityEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    cityEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...CityEditionOverview_city
        ...City_city
      }
    }
  }
`;

export const cityEditionOverviewFocus = graphql`
  mutation CityEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    cityEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const cityMutationRelationAdd = graphql`
  mutation CityEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput!
  ) {
    cityEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...CityEditionOverview_city
        }
      }
    }
  }
`;

const cityMutationRelationDelete = graphql`
  mutation CityEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    cityEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...CityEditionOverview_city
      }
    }
  }
`;

export const cityEditionOverviewFragment = graphql`
  fragment CityEditionOverview_city on City {
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
          definition
          definition_type
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

const cityValidation = (t: (v: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable().max(5000, t('The value is too long')),
  latitude: Yup.lazy((value) => (value === '' ? Yup.string() : Yup.number().nullable().typeError(t('This field must be a number')))),
  longitude: Yup.lazy((value) => (value === '' ? Yup.string() : Yup.number().nullable().typeError(t('This field must be a number')))),
  x_opencti_workflow_id: Yup.object(),
});

interface CityEditionOverviewProps {
  cityRef: CityEditionOverview_city$key,
  context: readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[] | null
  enableReferences?: boolean
  handleClose: () => void
}

interface CityEditionFormValues {
  message?: string
  references?: Option[]
  createdBy?: Option
  x_opencti_workflow_id: Option
  objectMarking?: Option[]
}

const CityEditionOverview: FunctionComponent<CityEditionOverviewProps> = ({ cityRef, context, enableReferences = false, handleClose }) => {
  const { t } = useFormatter();

  const city = useFragment(cityEditionOverviewFragment, cityRef);

  const createdBy = convertCreatedBy(city);
  const objectMarking = convertMarkings(city);
  const status = convertStatus(t, city);

  const [commitRelationAdd] = useMutation<CityEditionOverviewRelationAddMutation>(cityMutationRelationAdd);
  const [commitRelationDelete] = useMutation<CityEditionOverviewRelationDeleteMutation>(cityMutationRelationDelete);
  const [commitFieldPatch] = useMutation<CityEditionOverviewFieldPatchMutation>(cityMutationFieldPatch);
  const [commitEditionFocus] = useMutation<CityEditionOverviewFocusMutation>(cityEditionOverviewFocus);

  const handleChangeCreatedBy = (_: string, value: Option) => {
    if (!enableReferences) {
      commitFieldPatch({
        variables: {
          id: city.id,
          input: [{ key: 'createdBy', value: [value.value] }],
        },
      });
    }
  };
  const handleChangeObjectMarking = (_: string, values: Option[]) => {
    if (!enableReferences) {
      const currentMarkingDefinitions = (city.objectMarking?.edges ?? []).map(({ node }) => ({ label: node.definition, value: node.id }));
      const added = R.difference(values, currentMarkingDefinitions).at(0);
      const removed = R.difference(currentMarkingDefinitions, values).at(0);
      if (added) {
        commitRelationAdd({
          variables: {
            id: city.id,
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
            id: city.id,
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
      cityValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitFieldPatch({
            variables: {
              id: city.id,
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
        id: city.id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  const onSubmit: FormikConfig<CityEditionFormValues>['onSubmit'] = (values, { setSubmitting }) => {
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
        id: city.id,
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
    name: city.name,
    description: city.description,
    latitude: city.latitude,
    longitude: city.longitude,
    x_opencti_workflow_id: status,
    createdBy,
    objectMarking,
    status,
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues as never}
      validationSchema={cityValidation(t)}
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
          {city?.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="City"
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
              id={city.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default CityEditionOverview;
