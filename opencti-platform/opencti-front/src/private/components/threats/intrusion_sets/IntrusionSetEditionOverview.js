import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import * as R from 'ramda';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

const intrusionSetMutationFieldPatch = graphql`
  mutation IntrusionSetEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    intrusionSetEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...IntrusionSetEditionOverview_intrusionSet
        ...IntrusionSet_intrusionSet
      }
    }
  }
`;

export const intrusionSetEditionOverviewFocus = graphql`
  mutation IntrusionSetEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    intrusionSetEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const intrusionSetMutationRelationAdd = graphql`
  mutation IntrusionSetEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    intrusionSetEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...IntrusionSetEditionOverview_intrusionSet
        }
      }
    }
  }
`;

const intrusionSetMutationRelationDelete = graphql`
  mutation IntrusionSetEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    intrusionSetEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...IntrusionSetEditionOverview_intrusionSet
      }
    }
  }
`;

const intrusionSetValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  confidence: Yup.number(),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
  references: Yup.array().required(t('This field is required')),
  x_opencti_workflow_id: Yup.object(),
});

const IntrusionSetEditionOverviewComponent = (props) => {
  const { intrusionSet, enableReferences, context, handleClose } = props;
  const { t } = useFormatter();

  const handleChangeFocus = (name) => commitMutation({
    mutation: intrusionSetEditionOverviewFocus,
    variables: {
      id: intrusionSet.id,
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
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: intrusionSetMutationFieldPatch,
      variables: {
        id: intrusionSet.id,
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
      intrusionSetValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: intrusionSetMutationFieldPatch,
            variables: {
              id: intrusionSet.id,
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
        mutation: intrusionSetMutationFieldPatch,
        variables: {
          id: intrusionSet.id,
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
      )(intrusionSet);
      const added = R.difference(values, currentMarkingDefinitions);
      const removed = R.difference(currentMarkingDefinitions, values);

      if (added.length > 0) {
        commitMutation({
          mutation: intrusionSetMutationRelationAdd,
          variables: {
            id: intrusionSet.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-marking',
            },
          },
        });
      }

      if (removed.length > 0) {
        commitMutation({
          mutation: intrusionSetMutationRelationDelete,
          variables: {
            id: intrusionSet.id,
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  };

  const createdBy = convertCreatedBy(intrusionSet);
  const objectMarking = convertMarkings(intrusionSet);
  const status = convertStatus(t, intrusionSet);
  const killChainPhases = R.pipe(
    R.pathOr([], ['killChainPhases', 'edges']),
    R.map((n) => ({
      label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
      value: n.node.id,
    })),
  )(intrusionSet);
  const initialValues = R.pipe(
    R.assoc('createdBy', createdBy),
    R.assoc('killChainPhases', killChainPhases),
    R.assoc('x_opencti_workflow_id', status),
    R.assoc('objectMarking', objectMarking),
    R.pick([
      'name',
      'confidence',
      'description',
      'createdBy',
      'killChainPhases',
      'objectMarking',
      'x_opencti_workflow_id',
    ]),
  )(intrusionSet);
  return (
  <Formik
    enableReinitialize={true}
    initialValues={initialValues}
    validationSchema={intrusionSetValidation(t)}
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
        <ConfidenceField
          onFocus={handleChangeFocus}
          onSubmit={handleSubmitField}
          containerStyle={fieldSpacingContainerStyle}
          editContext={context}
          variant="edit"
          entityType="Intrusion-Set"
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
        {intrusionSet.workflowEnabled && (
          <StatusField
            name="x_opencti_workflow_id"
            type="Intrusion-Set"
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
            id={intrusionSet.id}
          />
        )}
      </Form>
    )}
  </Formik>
  );
};

export default createFragmentContainer(IntrusionSetEditionOverviewComponent, {
  intrusionSet: graphql`
      fragment IntrusionSetEditionOverview_intrusionSet on IntrusionSet {
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
    `,
});
