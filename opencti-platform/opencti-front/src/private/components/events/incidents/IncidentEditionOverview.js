import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import * as R from 'ramda';
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
  convertAssignees,
  convertCreatedBy,
  convertMarkings,
  convertStatus,
} from '../../../../utils/edition';
import OpenVocabField from '../../common/form/OpenVocabField';

import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';

const incidentMutationFieldPatch = graphql`
  mutation IncidentEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    incidentEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...IncidentEditionOverview_incident
      }
    }
  }
`;

export const incidentEditionOverviewFocus = graphql`
  mutation IncidentEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    incidentEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const incidentMutationRelationAdd = graphql`
  mutation IncidentEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    incidentEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...IncidentEditionOverview_incident
        }
      }
    }
  }
`;

const incidentMutationRelationDelete = graphql`
  mutation IncidentEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    incidentEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...IncidentEditionOverview_incident
      }
    }
  }
`;

const IncidentValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  confidence: Yup.number().required(t('This field is required')),
  incident_type: Yup.string(),
  severity: Yup.string(),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
  x_opencti_workflow_id: Yup.object(),
  references: Yup.array().required(t('This field is required')),
});

class IncidentEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: incidentEditionOverviewFocus,
      variables: {
        id: this.props.incident.id,
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
      R.assoc('objectAssignee', R.pluck('value', values.objectAssignee)),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: incidentMutationFieldPatch,
      variables: {
        id: this.props.incident.id,
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
    let finalValue = value;
    if (name === 'x_opencti_workflow_id') {
      finalValue = value.value;
    }
    IncidentValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: incidentMutationFieldPatch,
          variables: {
            id: this.props.incident.id,
            input: { key: name, value: finalValue || '' },
          },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedBy(name, value) {
    if (!this.props.enableReferences) {
      commitMutation({
        mutation: incidentMutationFieldPatch,
        variables: {
          id: this.props.incident.id,
          input: { key: 'createdBy', value: value.value || '' },
        },
      });
    }
  }

  handleChangeObjectMarking(name, values) {
    if (!this.props.enableReferences) {
      const { incident } = this.props;
      const currentMarkingDefinitions = R.pipe(
        R.pathOr([], ['objectMarking', 'edges']),
        R.map((n) => ({
          label: n.node.definition,
          value: n.node.id,
        })),
      )(incident);
      const added = R.difference(values, currentMarkingDefinitions);
      const removed = R.difference(currentMarkingDefinitions, values);
      if (added.length > 0) {
        commitMutation({
          mutation: incidentMutationRelationAdd,
          variables: {
            id: this.props.incident.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-marking',
            },
          },
        });
      }
      if (removed.length > 0) {
        commitMutation({
          mutation: incidentMutationRelationDelete,
          variables: {
            id: this.props.incident.id,
            toId: R.head(removed).value,
            relationship_type: 'object-marking',
          },
        });
      }
    }
  }

  handleChangeObjectAssignee(name, values) {
    if (!this.props.enableReferences) {
      const { report } = this.props;
      const currentAssignees = R.pipe(
        R.pathOr([], ['objectAssignee', 'edges']),
        R.map((n) => ({
          label: n.node.name,
          value: n.node.id,
        })),
      )(report);
      const added = R.difference(values, currentAssignees);
      const removed = R.difference(currentAssignees, values);
      if (added.length > 0) {
        commitMutation({
          mutation: incidentMutationRelationAdd,
          variables: {
            id: this.props.report.id,
            input: {
              toId: R.head(added).value,
              relationship_type: 'object-assignee',
            },
          },
        });
      }
      if (removed.length > 0) {
        commitMutation({
          mutation: incidentMutationRelationDelete,
          variables: {
            id: this.props.report.id,
            toId: R.head(removed).value,
            relationship_type: 'object-assignee',
          },
        });
      }
    }
  }

  render() {
    const { t, incident, context, enableReferences } = this.props;
    const isInferred = incident.is_inferred;
    const createdBy = convertCreatedBy(incident);
    const objectMarking = convertMarkings(incident);
    const objectAssignee = convertAssignees(incident);
    const status = convertStatus(t, incident);
    const initialValues = R.pipe(
      R.assoc('createdBy', createdBy),
      R.assoc('objectMarking', objectMarking),
      R.assoc('objectAssignee', objectAssignee),
      R.assoc('x_opencti_workflow_id', status),
      R.pick([
        'name',
        'confidence',
        'severity',
        'description',
        'createdBy',
        'incident_type',
        'objectMarking',
        'objectAssignee',
        'x_opencti_workflow_id',
      ]),
    )(incident);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={IncidentValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
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
              disabled={isInferred}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="name" />
              }
            />
            <ConfidenceField
              name="confidence"
              onFocus={this.handleChangeFocus.bind(this)}
              onChange={this.handleSubmitField.bind(this)}
              label={t('Confidence')}
              disabled={isInferred}
              fullWidth={true}
              containerStyle={fieldSpacingContainerStyle}
              editContext={context}
              variant="edit"
            />
            <OpenVocabField
              label={t('Incident type')}
              type="incident-type-ov"
              name="incident_type"
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              onChange={setFieldValue}
              containerStyle={fieldSpacingContainerStyle}
              variant="edit"
              multiple={false}
              editContext={context}
            />
            <OpenVocabField
              label={t('Severity')}
              type="incident-severity-ov"
              name="severity"
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              onChange={setFieldValue}
              containerStyle={fieldSpacingContainerStyle}
              variant="edit"
              multiple={false}
              editContext={context}
            />
            <Field
              component={MarkDownField}
              name="description"
              label={t('Description')}
              fullWidth={true}
              multiline={true}
              disabled={isInferred}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="description" />
              }
            />
            <ObjectAssigneeField
              name="objectAssignee"
              style={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldname="objectAssignee"
                />
              }
              onChange={this.handleChangeObjectAssignee.bind(this)}
            />
            {incident.workflowEnabled && (
              <StatusField
                name="x_opencti_workflow_id"
                type="Incident"
                onFocus={this.handleChangeFocus.bind(this)}
                onChange={this.handleSubmitField.bind(this)}
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
              onChange={this.handleChangeCreatedBy.bind(this)}
            />
            <ObjectMarkingField
              name="objectMarking"
              style={{ marginTop: 20, width: '100%' }}
              disabled={isInferred}
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
                validateForm={validateForm}
                setFieldValue={setFieldValue}
                values={values}
              />
            )}
          </Form>
        )}
      </Formik>
    );
  }
}

IncidentEditionOverviewComponent.propTypes = {
  t: PropTypes.func,
  incident: PropTypes.object,
  enableReferences: PropTypes.bool,
  context: PropTypes.array,
};

const IncidentEditionOverview = createFragmentContainer(
  IncidentEditionOverviewComponent,
  {
    incident: graphql`
      fragment IncidentEditionOverview_incident on Incident {
        id
        name
        confidence
        description
        incident_type
        severity
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
        objectAssignee {
          edges {
            node {
              id
              name
              entity_type
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
        is_inferred
      }
    `,
  },
);

export default inject18n(IncidentEditionOverview);
