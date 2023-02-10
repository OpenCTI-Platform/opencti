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
import DateTimePickerField from '../../../../components/DateTimePickerField';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { convertCreatedBy, convertMarkings, convertStatus } from '../../../../utils/edition';
import StatusField from '../../common/form/StatusField';
import { buildDate, parse } from '../../../../utils/Time';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ConfidenceField from '../../common/form/ConfidenceField';

const infrastructureMutationFieldPatch = graphql`
  mutation InfrastructureEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    infrastructureEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...InfrastructureEditionOverview_infrastructure
        ...Infrastructure_infrastructure
      }
    }
  }
`;

export const infrastructureEditionOverviewFocus = graphql`
  mutation InfrastructureEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    infrastructureEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const infrastructureMutationRelationAdd = graphql`
  mutation InfrastructureEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    infrastructureEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...InfrastructureEditionOverview_infrastructure
        }
      }
    }
  }
`;

const infrastructureMutationRelationDelete = graphql`
  mutation InfrastructureEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    infrastructureEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...InfrastructureEditionOverview_infrastructure
      }
    }
  }
`;

const infrastructureValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
  infrastructure_types: Yup.array().nullable(),
  first_seen: Yup.date()
    .nullable()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  last_seen: Yup.date()
    .nullable()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  references: Yup.array().required(t('This field is required')),
  x_opencti_workflow_id: Yup.object(),
  confidence: Yup.number(),
});

const InfrastructureEditionOverviewComponent = (props) => {
  const { infrastructure, enableReferences, context, handleClose } = props;
  const { t } = useFormatter();

  const handleChangeFocus = (name) => commitMutation({
    mutation: infrastructureEditionOverviewFocus,
    variables: {
      id: infrastructure.id,
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
      R.assoc('infrastructure_types', values.infrastructure_types),
      R.assoc(
        'first_seen',
        values.first_seen ? parse(values.first_seen).format() : null,
      ),
      R.assoc(
        'last_seen',
        values.last_seen ? parse(values.last_seen).format() : null,
      ),
      R.toPairs,
      R.map((n) => ({ key: n[0], value: adaptFieldValue(n[1]) })),
    )(values);
    commitMutation({
      mutation: infrastructureMutationFieldPatch,
      variables: {
        id: infrastructure.id,
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
      infrastructureValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: infrastructureMutationFieldPatch,
            variables: {
              id: infrastructure.id,
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
        mutation: infrastructureMutationFieldPatch,
        variables: {
          id: infrastructure.id,
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
      )(infrastructure);
      const added = R.difference(values, currentMarkingDefinitions);
      const removed = R.difference(currentMarkingDefinitions, values);
      if (added.length > 0) {
        commitMutation({
          mutation: infrastructureMutationRelationAdd,
          variables: {
            id: infrastructure.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-marking',
            },
          },
        });
      }
      if (removed.length > 0) {
        commitMutation({
          mutation: infrastructureMutationRelationDelete,
          variables: {
            id: infrastructure.id,
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
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
      )(infrastructure);
      const added = R.difference(values, currentKillChainPhases);
      const removed = R.difference(currentKillChainPhases, values);
      if (added.length > 0) {
        commitMutation({
          mutation: infrastructureMutationRelationAdd,
          variables: {
            id: infrastructure.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'kill-chain-phase',
            },
          },
        });
      }

      if (removed.length > 0) {
        commitMutation({
          mutation: infrastructureMutationRelationDelete,
          variables: {
            id: infrastructure.id,
            toId: R.head(removed).value,
            relationship_type: 'kill-chain-phase',
          },
        });
      }
    }
  };

  const createdBy = convertCreatedBy(infrastructure);
  const objectMarking = convertMarkings(infrastructure);
  const status = convertStatus(t, infrastructure);
  const killChainPhases = R.pipe(
    R.pathOr([], ['killChainPhases', 'edges']),
    R.map((n) => ({
      label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
      value: n.node.id,
    })),
  )(infrastructure);
  const initialValues = R.pipe(
    R.assoc('createdBy', createdBy),
    R.assoc('killChainPhases', killChainPhases),
    R.assoc('objectMarking', objectMarking),
    R.assoc('x_opencti_workflow_id', status),
    R.assoc('first_seen', buildDate(infrastructure.first_seen)),
    R.assoc('last_seen', buildDate(infrastructure.last_seen)),
    R.assoc(
      'infrastructure_types',
      infrastructure.infrastructure_types
        ? infrastructure.infrastructure_types
        : [],
    ),
    R.pick([
      'name',
      'description',
      'infrastructure_types',
      'confidence',
      'first_seen',
      'last_seen',
      'createdBy',
      'killChainPhases',
      'objectMarking',
      'x_opencti_workflow_id',
      'confidence',
    ]),
  )(infrastructure);
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={infrastructureValidation(t)}
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
          <OpenVocabField
            label={t('Infrastructure types')}
            type="infrastructure-type-ov"
            name="infrastructure_types"
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            variant="edit"
            multiple={true}
            editContext={context}
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
            component={DateTimePickerField}
            name="first_seen"
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            TextFieldProps={{
              label: t('First seen'),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
              helperText: (
                <SubscriptionFocus context={context} fieldName="first_seen" />
              ),
            }}
          />
          <Field
            component={DateTimePickerField}
            name="last_seen"
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            TextFieldProps={{
              label: t('Last seen'),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
              helperText: (
                <SubscriptionFocus context={context} fieldName="last_seen" />
              ),
            }}
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
          {infrastructure.workflowEnabled && (
            <StatusField
              name="x_opencti_workflow_id"
              type="Infrastructure"
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
              id={infrastructure.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default createFragmentContainer(InfrastructureEditionOverviewComponent, {
  infrastructure: graphql`
    fragment InfrastructureEditionOverview_infrastructure on Infrastructure {
      id
      name
      description
      confidence
      first_seen
      last_seen
      infrastructure_types
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
