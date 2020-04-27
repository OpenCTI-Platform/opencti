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

const threatActorMutationFieldPatch = graphql`
  mutation ThreatActorEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    threatActorEdit(id: $id) {
      fieldPatch(input: $input) {
        ...ThreatActorEditionOverview_threatActor
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
    $input: RelationAddInput!
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
    $relationId: ID!
  ) {
    threatActorEdit(id: $id) {
      relationDelete(relationId: $relationId) {
        ...ThreatActorEditionOverview_threatActor
      }
    }
  }
`;

const threatActorValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
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

  handleSubmitField(name, value) {
    threatActorValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: threatActorMutationFieldPatch,
          variables: {
            id: this.props.threatActor.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedByRef(name, value) {
    const { threatActor } = this.props;
    const currentCreatedByRef = {
      label: pathOr(null, ['createdByRef', 'node', 'name'], threatActor),
      value: pathOr(null, ['createdByRef', 'node', 'id'], threatActor),
      relation: pathOr(null, ['createdByRef', 'relation', 'id'], threatActor),
    };

    if (currentCreatedByRef.value === null) {
      commitMutation({
        mutation: threatActorMutationRelationAdd,
        variables: {
          id: this.props.threatActor.id,
          input: {
            fromRole: 'so',
            toRole: 'creator',
            toId: value.value,
            through: 'created_by_ref',
          },
        },
      });
    } else if (currentCreatedByRef.value !== value.value) {
      commitMutation({
        mutation: threatActorMutationRelationDelete,
        variables: {
          id: this.props.threatActor.id,
          relationId: currentCreatedByRef.relation,
        },
      });
      if (value.value) {
        commitMutation({
          mutation: threatActorMutationRelationAdd,
          variables: {
            id: this.props.threatActor.id,
            input: {
              fromRole: 'so',
              toRole: 'creator',
              toId: value.value,
              through: 'created_by_ref',
            },
          },
        });
      }
    }
  }

  handleChangeMarkingDefinitions(name, values) {
    const { threatActor } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(threatActor);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: threatActorMutationRelationAdd,
        variables: {
          id: this.props.threatActor.id,
          input: {
            fromRole: 'so',
            toRole: 'marking',
            toId: head(added).value,
            through: 'object_marking_refs',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: threatActorMutationRelationDelete,
        variables: {
          id: this.props.threatActor.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  render() {
    const { t, threatActor, context } = this.props;
    const createdByRef = pathOr(null, ['createdByRef', 'node', 'name'], threatActor) === null
      ? ''
      : {
        label: pathOr(null, ['createdByRef', 'node', 'name'], threatActor),
        value: pathOr(null, ['createdByRef', 'node', 'id'], threatActor),
        relation: pathOr(
          null,
          ['createdByRef', 'relation', 'id'],
          threatActor,
        ),
      };
    const killChainPhases = pipe(
      pathOr([], ['killChainPhases', 'edges']),
      map((n) => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(threatActor);
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(threatActor);
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
    )(threatActor);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={threatActorValidation(t)}
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

ThreatActorEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  threatActor: PropTypes.object,
  context: PropTypes.array,
};

const ThreatActorEditionOverview = createFragmentContainer(
  ThreatActorEditionOverviewComponent,
  {
    threatActor: graphql`
      fragment ThreatActorEditionOverview_threatActor on ThreatActor {
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
)(ThreatActorEditionOverview);
