import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import StatusField from '../../common/form/StatusField';
import {
  convertCreatedBy,
  convertMarkings,
  convertStatus,
} from '../../../../utils/edition';
import OpenVocabField from '../../common/form/OpenVocabField';

const threatActorMutationFieldPatch = graphql`
  mutation ThreatActorEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    threatActorEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...ThreatActorEditionOverview_threatActor
        ...ThreatActor_threatActor
      }
    }
  }
`;

export const threatActorEditionOverviewFocus = graphql`
  mutation ThreatActorEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    threatActorEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const threatActorMutationRelationAdd = graphql`
  mutation ThreatActorEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    threatActorEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...ThreatActorEditionOverview_threatActor
        }
      }
    }
  }
`;

const threatActorMutationRelationDelete = graphql`
  mutation ThreatActorEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    threatActorEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...ThreatActorEditionOverview_threatActor
      }
    }
  }
`;

const threatActorValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  threat_actor_types: Yup.array(),
  confidence: Yup.number().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
  references: Yup.array().required(t('This field is required')),
  x_opencti_workflow_id: Yup.object(),
});

class ThreatActorEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: threatActorEditionOverviewFocus,
      variables: {
        id: this.props.threatActor.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  onSubmit(values, { setSubmitting }) {
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
      mutation: threatActorMutationFieldPatch,
      variables: {
        id: this.props.threatActor.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        this.props.handleClose();
      },
    });
  }

  handleSubmitField(name, value) {
    if (!this.props.enableReferences) {
      let finalValue = value;
      if (name === 'x_opencti_workflow_id') {
        finalValue = value.value;
      }
      threatActorValidation(this.props.t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: threatActorMutationFieldPatch,
            variables: {
              id: this.props.threatActor.id,
              input: { key: name, value: finalValue ?? '' },
            },
          });
        })
        .catch(() => false);
    }
  }

  handleChangeCreatedBy(name, value) {
    if (!this.props.enableReferences) {
      commitMutation({
        mutation: threatActorMutationFieldPatch,
        variables: {
          id: this.props.threatActor.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  }

  handleChangeObjectMarking(name, values) {
    if (!this.props.enableReferences) {
      const { threatActor } = this.props;
      const currentMarkingDefinitions = R.pipe(
        R.pathOr([], ['objectMarking', 'edges']),
        R.map((n) => ({
          label: n.node.definition,
          value: n.node.id,
        })),
      )(threatActor);
      const added = R.difference(values, currentMarkingDefinitions);
      const removed = R.difference(currentMarkingDefinitions, values);
      if (added.length > 0) {
        commitMutation({
          mutation: threatActorMutationRelationAdd,
          variables: {
            id: this.props.threatActor.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-marking',
            },
          },
        });
      }
      if (removed.length > 0) {
        commitMutation({
          mutation: threatActorMutationRelationDelete,
          variables: {
            id: this.props.threatActor.id,
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  }

  render() {
    const { t, threatActor, context, enableReferences } = this.props;
    const createdBy = convertCreatedBy(threatActor);
    const objectMarking = convertMarkings(threatActor);
    const status = convertStatus(t, threatActor);
    const killChainPhases = R.pipe(
      R.pathOr([], ['killChainPhases', 'edges']),
      R.map((n) => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
      })),
    )(threatActor);
    const initialValues = R.pipe(
      R.assoc('createdBy', createdBy),
      R.assoc('killChainPhases', killChainPhases),
      R.assoc('objectMarking', objectMarking),
      R.assoc('x_opencti_workflow_id', status),
      R.assoc(
        'threat_actor_types',
        threatActor.threat_actor_types ? threatActor.threat_actor_types : [],
      ),
      R.pick([
        'name',
        'threat_actor_types',
        'confidence',
        'description',
        'createdBy',
        'killChainPhases',
        'objectMarking',
        'x_opencti_workflow_id',
      ]),
    )(threatActor);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={{ ...initialValues, references: [] }}
        validationSchema={threatActorValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
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
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="name" />
              }
            />
            <OpenVocabField
              type="threat-actor-type-ov"
              name="threat_actor_types"
              label={t('Threat actor types')}
              containerStyle={{ width: '100%', marginTop: 20 }}
              multiple={true}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              onChange={(name, value) => setFieldValue(name, value)}
            />
            <ConfidenceField
              name="confidence"
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              label={t('Confidence')}
              fullWidth={true}
              containerStyle={{ width: '100%', marginTop: 20 }}
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
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="description" />
              }
            />
            {threatActor.workflowEnabled && (
              <StatusField
                name="x_opencti_workflow_id"
                type="Threat-Actor"
                onFocus={this.handleChangeFocus.bind(this)}
                onChange={this.handleSubmitField.bind(this)}
                setFieldValue={setFieldValue}
                style={{ marginTop: 20 }}
                helpertext={
                  <SubscriptionFocus
                    context={context}
                    field="x_opencti_workflow_id"
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
              onChange={this.handleChangeCreatedBy.bind(this)}
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
              onChange={this.handleChangeObjectMarking.bind(this)}
            />
            {enableReferences && (
              <CommitMessage
                submitForm={submitForm}
                disabled={isSubmitting}
                setFieldValue={setFieldValue}
                open={false}
                values={values.references}
                id={threatActor.id}
              />
            )}
          </Form>
        )}
      </Formik>
    );
  }
}

ThreatActorEditionOverviewComponent.propTypes = {
  theme: PropTypes.object,
  t: PropTypes.func,
  threatActor: PropTypes.object,
  enableReferences: PropTypes.bool,
  context: PropTypes.array,
  handleClose: PropTypes.func,
};

const ThreatActorEditionOverview = createFragmentContainer(
  ThreatActorEditionOverviewComponent,
  {
    threatActor: graphql`
      fragment ThreatActorEditionOverview_threatActor on ThreatActor {
        id
        name
        threat_actor_types
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
  },
);

export default inject18n(ThreatActorEditionOverview);
