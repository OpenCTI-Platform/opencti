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
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
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

const attackPatternMutationFieldPatch = graphql`
  mutation AttackPatternEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    attackPatternEdit(id: $id) {
      fieldPatch(input: $input) {
        ...AttackPatternEditionOverview_attackPattern
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
    $input: RelationAddInput!
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
    $relationId: ID!
  ) {
    attackPatternEdit(id: $id) {
      relationDelete(relationId: $relationId) {
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
});

class AttackPatternEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: attackPatternEditionOverviewFocus,
      variables: {
        id: this.props.attackPattern.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    attackPatternValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: attackPatternMutationFieldPatch,
          variables: {
            id: this.props.attackPattern.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedByRef(name, value) {
    const { attackPattern } = this.props;
    const currentCreatedByRef = {
      label: pathOr(null, ['createdByRef', 'node', 'name'], attackPattern),
      value: pathOr(null, ['createdByRef', 'node', 'id'], attackPattern),
      relation: pathOr(null, ['createdByRef', 'relation', 'id'], attackPattern),
    };

    if (currentCreatedByRef.value === null) {
      commitMutation({
        mutation: attackPatternMutationRelationAdd,
        variables: {
          id: this.props.attackPattern.id,
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
        mutation: attackPatternMutationRelationDelete,
        variables: {
          id: this.props.attackPattern.id,
          relationId: currentCreatedByRef.relation,
        },
      });
      if (value.value) {
        commitMutation({
          mutation: attackPatternMutationRelationAdd,
          variables: {
            id: this.props.attackPattern.id,
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

  handleChangeKillChainPhases(name, values) {
    const { attackPattern } = this.props;
    const currentKillChainPhases = pipe(
      pathOr([], ['killChainPhases', 'edges']),
      map((n) => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(attackPattern);

    const added = difference(values, currentKillChainPhases);
    const removed = difference(currentKillChainPhases, values);

    if (added.length > 0) {
      commitMutation({
        mutation: attackPatternMutationRelationAdd,
        variables: {
          id: this.props.attackPattern.id,
          input: {
            fromRole: 'phase_belonging',
            toId: head(added).value,
            toRole: 'kill_chain_phase',
            through: 'kill_chain_phases',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: attackPatternMutationRelationDelete,
        variables: {
          id: this.props.attackPattern.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  handleChangeMarkingDefinitions(name, values) {
    const { attackPattern } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(attackPattern);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: attackPatternMutationRelationAdd,
        variables: {
          id: head(added).value,
          input: {
            fromRole: 'so',
            toId: this.props.attackPattern.id,
            toRole: 'marking',
            through: 'object_marking_refs',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: attackPatternMutationRelationDelete,
        variables: {
          id: this.props.attackPattern.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  render() {
    const { t, attackPattern, context } = this.props;
    const createdByRef = pathOr(null, ['createdByRef', 'node', 'name'], attackPattern) === null
      ? ''
      : {
        label: pathOr(
          null,
          ['createdByRef', 'node', 'name'],
          attackPattern,
        ),
        value: pathOr(null, ['createdByRef', 'node', 'id'], attackPattern),
        relation: pathOr(
          null,
          ['createdByRef', 'relation', 'id'],
          attackPattern,
        ),
      };
    const killChainPhases = pipe(
      pathOr([], ['killChainPhases', 'edges']),
      map((n) => ({
        label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(attackPattern);
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(attackPattern);
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
    )(attackPattern);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={attackPatternValidation(t)}
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
              onChange={this.handleChangeKillChainPhases.bind(this)}
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

AttackPatternEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  attackPattern: PropTypes.object,
  context: PropTypes.array,
};

const AttackPatternEditionOverview = createFragmentContainer(
  AttackPatternEditionOverviewComponent,
  {
    attackPattern: graphql`
      fragment AttackPatternEditionOverview_attackPattern on AttackPattern {
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
        killChainPhases {
          edges {
            node {
              id
              kill_chain_name
              phase_name
              phase_order
            }
            relation {
              id
            }
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
)(AttackPatternEditionOverview);
