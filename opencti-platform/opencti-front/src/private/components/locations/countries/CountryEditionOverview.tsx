import React, { FunctionComponent } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import {
  convertCreatedBy,
  convertMarkings,
  convertStatus,
} from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { CountryEditionOverview_country$key } from './__generated__/CountryEditionOverview_country.graphql';
import { Option } from '../../common/form/ReferenceField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';

const countryMutationFieldPatch = graphql`
  mutation CountryEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    countryEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...CountryEditionOverview_country
        ...Country_country
      }
    }
  }
`;

export const countryEditionOverviewFocus = graphql`
  mutation CountryEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    countryEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const countryMutationRelationAdd = graphql`
  mutation CountryEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput!
  ) {
    countryEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...CountryEditionOverview_country
        }
      }
    }
  }
`;

const countryMutationRelationDelete = graphql`
  mutation CountryEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    countryEdit(id: $id) {
      relationDelete(
        toId: $toId, 
        relationship_type: $relationship_type
      ) {
        ...CountryEditionOverview_country
      }
    }
  }
`;

const countryEditionOverviewFragment = graphql`
  fragment CountryEditionOverview_country on Country {
    id
    name
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

const countryValidation = (t: (v: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
  x_opencti_workflow_id: Yup.object(),
});

interface CountryEditionOverviewProps {
  countryRef: CountryEditionOverview_country$key,
  context: readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[] | null
  enableReferences?: boolean
  handleClose: () => void
}

interface CountryEditionFormValues {
  message: string
  references: Option[],
  x_opencti_workflow_id: Option
  createdBy: Option
  objectMarking: Option[]
}

const CountryEditionOverviewComponent: FunctionComponent<CountryEditionOverviewProps> = ({
  countryRef,
  context,
  enableReferences = false,
  handleClose,
}) => {
  const { t } = useFormatter();
  const country = useFragment(countryEditionOverviewFragment, countryRef);
  const createdBy = convertCreatedBy(country);
  const objectMarking = convertMarkings(country);
  const status = convertStatus(t, country);

  const [commitRelationAdd] = useMutation(countryMutationRelationAdd);
  const [commitRelationDelete] = useMutation(countryMutationRelationDelete);
  const [commitFieldPatch] = useMutation(countryMutationFieldPatch);
  const [commitEditionFocus] = useMutation(countryEditionOverviewFocus);

  const handleChangeFocus = (name: string) => {
    commitEditionFocus({
      variables: {
        id: country.id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  const onSubmit: FormikConfig<CountryEditionFormValues>['onSubmit'] = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitFieldPatch({
      variables: {
        id: country.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleChangeCreatedBy = (_: string, value: Option) => {
    if (!enableReferences) {
      commitFieldPatch({
        variables: {
          id: country.id,
          input: { key: 'createdBy', value: [value.value] },
        },
      });
    }
  };

  const handleChangeObjectMarking = (_: string, values: Option[]) => {
    if (!enableReferences) {
      const currentMarkingDefinitions = (country.objectMarking?.edges ?? []).map((n) => ({ label: n?.node.definition, value: n?.node.id }));
      const added = R.difference(values, currentMarkingDefinitions).at(0);
      const removed = R.difference(currentMarkingDefinitions, values).at(0);
      if (added) {
        commitRelationAdd({
          variables: {
            id: country.id,
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
            id: country.id,
            toId: removed.value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  };
  const handleSubmitField = (name: string, value: Option | string) => {
    if (!enableReferences) {
      let finalValue: unknown = value as string;
      if (name === 'x_opencti_workflow_id') {
        finalValue = (value as Option).value;
      }
      countryValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitFieldPatch({
            variables: {
              id: country.id,
              input: { key: name, value: finalValue ?? '' },
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = R.pipe(
    R.assoc('createdBy', createdBy),
    R.assoc('objectMarking', objectMarking),
    R.assoc('x_opencti_workflow_id', status),
    R.pick([
      'name',
      'description',
      'createdBy',
      'objectMarking',
      'x_opencti_workflow_id',
    ]),
  )(country);

  return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues as never}
        validationSchema={countryValidation(t)}
        onSubmit={onSubmit}
      >
        {({
          submitForm,
          isSubmitting,
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
            {country?.workflowEnabled && (
              <StatusField
                name="x_opencti_workflow_id"
                type="Country"
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
                <SubscriptionFocus context={context} fieldname="objectMarking" />
              }
              onChange={handleChangeObjectMarking}
            />
            {enableReferences && (
              <CommitMessage
                submitForm={submitForm}
                disabled={isSubmitting}
                setFieldValue={setFieldValue}
                open={false}
                values={values.references}
                id={country.id}
              />
            )}
          </Form>
        )}
      </Formik>
  );
};

export default CountryEditionOverviewComponent;
