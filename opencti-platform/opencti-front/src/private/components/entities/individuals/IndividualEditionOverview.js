import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';

const individualMutationFieldPatch = graphql`
  mutation IndividualEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    individualEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...IndividualEditionOverview_individual
        ...Individual_individual
      }
    }
  }
`;

export const individualEditionOverviewFocus = graphql`
  mutation IndividualEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    individualEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const individualMutationRelationAdd = graphql`
  mutation IndividualEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    individualEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...IndividualEditionOverview_individual
        }
      }
    }
  }
`;

const individualMutationRelationDelete = graphql`
  mutation IndividualEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    individualEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...IndividualEditionOverview_individual
      }
    }
  }
`;

const individualValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
  contact_information: Yup.string().nullable(),
  references: Yup.array().required(t('This field is required')),
  x_opencti_workflow_id: Yup.object(),
});

const IndividualEditionOverviewComponent = (props) => {
  const { individual, enableReferences, context, handleClose } = props;
  const { t } = useFormatter();

  const handleChangeFocus = (name) => commitMutation({
    mutation: individualEditionOverviewFocus,
    variables: {
      id: individual.id,
      input: {
        focusOn: name,
      },
    },
  });

  const onSubmit = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc('x_opencti_workflow_id', values.x_opencti_workflow_id?.value),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.toPairs,
      R.map((n) => ({ key: n[0], value: adaptFieldValue(n[1]) })),
    )(values);
    commitMutation({
      mutation: individualMutationFieldPatch,
      variables: {
        id: individual.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleSubmitField = (name, value) => {
    if (!enableReferences) {
      let finalValue = value;
      if (name === 'x_opencti_workflow_id') {
        finalValue = value.value;
      }
      individualValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: individualMutationFieldPatch,
            variables: {
              id: individual.id,
              input: { key: name, value: finalValue ?? '' },
            },
          });
        })
        .catch(() => false);
    }
  };

  const handleChangeCreatedBy = (name, value) => {
    if (!enableReferences) {
      commitMutation({
        mutation: individualMutationFieldPatch,
        variables: {
          id: individual.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  };

  const handleChangeObjectMarking = (name, values) => {
    if (!enableReferences) {
      const currentMarkingDefinitions = R.pipe(
        R.pathOr([], ['objectMarking', 'edges']),
        R.map((n) => ({
          label: n.node.definition,
          value: n.node.id,
        })),
      )(individual);
      const added = R.difference(values, currentMarkingDefinitions);
      const removed = R.difference(currentMarkingDefinitions, values);
      if (added.length > 0) {
        commitMutation({
          mutation: individualMutationRelationAdd,
          variables: {
            id: individual.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-marking',
            },
          },
        });
      }
      if (removed.length > 0) {
        commitMutation({
          mutation: individualMutationRelationDelete,
          variables: {
            id: individual.id,
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  };

  const external = individual.external === true;
  const createdBy = convertCreatedBy(individual);
  const objectMarking = convertMarkings(individual);
  const status = convertStatus(t, individual);
  const initialValues = R.pipe(
    R.assoc('createdBy', createdBy),
    R.assoc('objectMarking', objectMarking),
    R.assoc('x_opencti_workflow_id', status),
    R.pick([
      'name',
      'description',
      'contact_information',
      'createdBy',
      'objectMarking',
      'x_opencti_workflow_id',
    ]),
  )(individual);
  return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={individualValidation(t)}
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
              disabled={external}
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
              name="contact_information"
              label={t('Contact information')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus
                  context={context}
                  fieldName="contact_information"
                />
              }
            />
            {individual.workflowEnabled && (
              <StatusField
                name="x_opencti_workflow_id"
                type="Individual"
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
                setFieldValue={setFieldValue}
                open={false}
                values={values.references}
                id={individual.id}
              />
            )}
          </Form>
        )}
      </Formik>
  );
};

export default createFragmentContainer(IndividualEditionOverviewComponent, {
  individual: graphql`
      fragment IndividualEditionOverview_individual on Individual {
        id
        name
        description
        contact_information
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
    `,
});
