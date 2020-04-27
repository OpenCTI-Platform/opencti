import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import {
  assoc,
  compose,
  map,
  pathOr,
  pipe,
  pick,
  difference,
  head,
} from 'ramda';
import * as Yup from 'yup';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import CreatedByRefField from '../../common/form/CreatedByRefField';
import MarkingDefinitionsField from '../../common/form/MarkingDefinitionsField';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'hidden',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: '30px 30px 30px 30px',
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  importButton: {
    position: 'absolute',
    top: 30,
    right: 30,
  },
});

const incidentMutationFieldPatch = graphql`
  mutation IncidentEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    incidentEdit(id: $id) {
      fieldPatch(input: $input) {
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
    $input: RelationAddInput!
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
    $relationId: ID!
  ) {
    incidentEdit(id: $id) {
      relationDelete(relationId: $relationId) {
        ...IncidentEditionOverview_incident
      }
    }
  }
`;

const incidentValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
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

  handleSubmitField(name, value) {
    incidentValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: incidentMutationFieldPatch,
          variables: {
            id: this.props.incident.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedByRef(name, value) {
    const { incident } = this.props;
    const currentCreatedByRef = {
      label: pathOr(null, ['createdByRef', 'node', 'name'], incident),
      value: pathOr(null, ['createdByRef', 'node', 'id'], incident),
      relation: pathOr(null, ['createdByRef', 'relation', 'id'], incident),
    };

    if (currentCreatedByRef.value === null) {
      commitMutation({
        mutation: incidentMutationRelationAdd,
        variables: {
          id: this.props.incident.id,
          input: {
            fromRole: 'so',
            toId: value.value,
            toRole: 'creator',
            through: 'created_by_ref',
          },
        },
      });
    } else if (currentCreatedByRef.value !== value.value) {
      commitMutation({
        mutation: incidentMutationRelationDelete,
        variables: {
          id: this.props.incident.id,
          relationId: currentCreatedByRef.relation,
        },
      });
      if (value.value) {
        commitMutation({
          mutation: incidentMutationRelationAdd,
          variables: {
            id: this.props.incident.id,
            input: {
              fromRole: 'so',
              toId: value.value,
              toRole: 'creator',
              through: 'created_by_ref',
            },
          },
        });
      }
    }
  }

  handleChangeMarkingDefinitions(name, values) {
    const { incident } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(incident);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: incidentMutationRelationAdd,
        variables: {
          id: this.props.incident.id,
          input: {
            fromRole: 'so',
            toId: head(added).value,
            toRole: 'marking',
            through: 'object_marking_refs',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: incidentMutationRelationDelete,
        variables: {
          id: this.props.incident.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  render() {
    const { t, incident, context } = this.props;
    const createdByRef = pathOr(null, ['createdByRef', 'node', 'name'], incident) === null
      ? ''
      : {
        label: pathOr(null, ['createdByRef', 'node', 'name'], incident),
        value: pathOr(null, ['createdByRef', 'node', 'id'], incident),
        relation: pathOr(
          null,
          ['createdByRef', 'relation', 'id'],
          incident,
        ),
      };
    const killChainPhases = pipe(
      pathOr([], ['killChainPhases', 'edges']),
      map((n) => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(incident);
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(incident);
    const initialValues = pipe(
      assoc('createdByRef', createdByRef),
      assoc('killChainPhases', killChainPhases),
      assoc('markingDefinitions', markingDefinitions),
      pick([
        'name',
        'description',
        'createdByRef',
        'killChainPhases',
        'markingDefinitions',
      ]),
    )(incident);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={incidentValidation(t)}
        onSubmit={() => true}
      >
        {({ setFieldValue }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              name="name"
              label={t('Name')}
              fullWidth={true}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="name" />
              }
            />
            <Field
              component={TextField}
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
            <CreatedByRefField
              name="createdByRef"
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              helpertext={
                <SubscriptionFocus context={context} fieldName="createdByRef" />
              }
              onChange={this.handleChangeCreatedByRef.bind(this)}
            />
            <MarkingDefinitionsField
              name="markingDefinitions"
              style={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="markingDefinitions"
                />
              }
              onChange={this.handleChangeMarkingDefinitions.bind(this)}
            />
          </Form>
        )}
      </Formik>
    );
  }
}

IncidentEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  incident: PropTypes.object,
  context: PropTypes.array,
};

const IncidentEditionOverview = createFragmentContainer(
  IncidentEditionOverviewComponent,
  {
    incident: graphql`
      fragment IncidentEditionOverview_incident on Incident {
        id
        name
        description
        createdByRef {
          node {
            id
            name
            entity_type
          }
          relation {
            id
          }
        }
        markingDefinitions {
          edges {
            node {
              id
              definition
              definition_type
            }
            relation {
              id
            }
          }
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(IncidentEditionOverview);
