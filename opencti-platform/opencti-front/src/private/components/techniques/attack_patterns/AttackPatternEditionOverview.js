import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import StatusField from '../../common/form/StatusField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';

const attackPatternMutationFieldPatch = graphql`
  mutation AttackPatternEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    attackPatternEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...AttackPatternEditionOverview_attackPattern
        ...AttackPattern_attackPattern
      }
    }
  }
`;

export const attackPatternEditionOverviewFocus = graphql`
  mutation AttackPatternEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    attackPatternEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const attackPatternMutationRelationAdd = graphql`
  mutation AttackPatternEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    attackPatternEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...AttackPatternEditionOverview_attackPattern
        }
      }
    }
  }
`;

const attackPatternMutationRelationDelete = graphql`
  mutation AttackPatternEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    attackPatternEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...AttackPatternEditionOverview_attackPattern
      }
    }
  }
`;

const attackPatternValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
  references: Yup.array().required(t('This field is required')),
  x_opencti_workflow_id: Yup.object(),
});

const AttackPatternEditionOverviewComponent = (props) => {
  const { attackPattern, enableReferences, context, handleClose } = props;
  const { t } = useFormatter();

  const handleChangeFocus = (name) => commitMutation({
    mutation: attackPatternEditionOverviewFocus,
    variables: {
      id: attackPattern.id,
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
      R.assoc('killChainPhases', R.pluck('value', values.killChainPhases)),
      R.toPairs,
      R.map((n) => ({ key: n[0], value: adaptFieldValue(n[1]) })),
    )(values);
    commitMutation({
      mutation: attackPatternMutationFieldPatch,
      variables: {
        id: attackPattern.id,
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
      attackPatternValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: attackPatternMutationFieldPatch,
            variables: {
              id: attackPattern.id,
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
        mutation: attackPatternMutationFieldPatch,
        variables: {
          id: attackPattern.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  };

  const handleChangeKillChainPhases = (name, values) => {
    if (!enableReferences) {
      const currentKillChainPhases = R.pipe(
        R.pathOr([], ['killChainPhases', 'edges']),
        R.map((n) => ({
          label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
          value: n.node.id,
        })),
      )(attackPattern);

      const added = R.difference(values, currentKillChainPhases);
      const removed = R.difference(currentKillChainPhases, values);

      if (added.length > 0) {
        commitMutation({
          mutation: attackPatternMutationRelationAdd,
          variables: {
            id: attackPattern.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'kill-chain-phase',
            },
          },
        });
      }

      if (removed.length > 0) {
        commitMutation({
          mutation: attackPatternMutationRelationDelete,
          variables: {
            id: attackPattern.id,
            toId: R.head(removed).value,
            relationship_type: 'kill-chain-phase',
          },
        });
      }
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
      )(attackPattern);

      const added = R.difference(values, currentMarkingDefinitions);
      const removed = R.difference(currentMarkingDefinitions, values);

      if (added.length > 0) {
        commitMutation({
          mutation: attackPatternMutationRelationAdd,
          variables: {
            id: attackPattern.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-marking',
            },
          },
        });
      }

      if (removed.length > 0) {
        commitMutation({
          mutation: attackPatternMutationRelationDelete,
          variables: {
            id: attackPattern.id,
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  };

  const createdBy = convertCreatedBy(attackPattern);
  const objectMarking = convertMarkings(attackPattern);
  const status = convertStatus(t, attackPattern);
  const killChainPhases = R.pipe(
    R.pathOr([], ['killChainPhases', 'edges']),
    R.map((n) => ({
      label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
      value: n.node.id,
    })),
  )(attackPattern);
  const initialValues = R.pipe(
    R.assoc('createdBy', createdBy),
    R.assoc('killChainPhases', killChainPhases),
    R.assoc('objectMarking', objectMarking),
    R.assoc('x_opencti_workflow_id', status),
    R.pick([
      'name',
      'description',
      'createdBy',
      'killChainPhases',
      'objectMarking',
      'x_opencti_workflow_id',
    ]),
  )(attackPattern);
  return (
      <Formik
        enableReinitialize={true}
        initialValues={{ ...initialValues, references: [] }}
        validationSchema={attackPatternValidation(t)}
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
            <KillChainPhasesField
              name="killChainPhases"
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="killChainPhases"
                />
              }
              onChange={handleChangeKillChainPhases}
            />
            {attackPattern.workflowEnabled && (
              <StatusField
                name="x_opencti_workflow_id"
                type="Attack-Pattern"
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
                id={attackPattern.id}
              />
            )}
          </Form>
        )}
      </Formik>
  );
};

export default createFragmentContainer(AttackPatternEditionOverviewComponent, {
  attackPattern: graphql`
      fragment AttackPatternEditionOverview_attackPattern on AttackPattern {
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
        killChainPhases {
          edges {
            node {
              id
              kill_chain_name
              phase_name
              x_opencti_order
            }
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
