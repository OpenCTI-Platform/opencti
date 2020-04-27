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

const stixObservableMutationFieldPatch = graphql`
  mutation StixObservableEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    stixObservableEdit(id: $id) {
      fieldPatch(input: $input) {
        ...StixObservableEditionOverview_stixObservable
      }
    }
  }
`;

export const stixObservableEditionOverviewFocus = graphql`
  mutation StixObservableEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    stixObservableEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const stixObservableMutationRelationAdd = graphql`
  mutation StixObservableEditionOverviewRelationAddMutation(
    $id: ID!
    $input: RelationAddInput!
  ) {
    stixObservableEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...StixObservableEditionOverview_stixObservable
        }
      }
    }
  }
`;

const stixObservableMutationRelationDelete = graphql`
  mutation StixObservableEditionOverviewRelationDeleteMutation(
    $id: ID!
    $relationId: ID!
  ) {
    stixObservableEdit(id: $id) {
      relationDelete(relationId: $relationId) {
        ...StixObservableEditionOverview_stixObservable
      }
    }
  }
`;

const stixObservableValidation = (t) => Yup.object().shape({
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class StixObservableEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: stixObservableEditionOverviewFocus,
      variables: {
        id: this.props.stixObservable.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    stixObservableValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: stixObservableMutationFieldPatch,
          variables: {
            id: this.props.stixObservable.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedByRef(name, value) {
    const { stixObservable } = this.props;
    const currentCreatedByRef = {
      label: pathOr(null, ['createdByRef', 'node', 'name'], stixObservable),
      value: pathOr(null, ['createdByRef', 'node', 'id'], stixObservable),
      relation: pathOr(
        null,
        ['createdByRef', 'relation', 'id'],
        stixObservable,
      ),
    };

    if (currentCreatedByRef.value === null) {
      commitMutation({
        mutation: stixObservableMutationRelationAdd,
        variables: {
          id: this.props.stixObservable.id,
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
        mutation: stixObservableMutationRelationDelete,
        variables: {
          id: this.props.stixObservable.id,
          relationId: currentCreatedByRef.relation,
        },
      });
      if (value.value) {
        commitMutation({
          mutation: stixObservableMutationRelationAdd,
          variables: {
            id: this.props.stixObservable.id,
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
    const { stixObservable } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(stixObservable);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: stixObservableMutationRelationAdd,
        variables: {
          id: this.props.stixObservable.id,
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
        mutation: stixObservableMutationRelationDelete,
        variables: {
          id: this.props.stixObservable.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  render() {
    const { t, stixObservable, context } = this.props;
    const createdByRef = pathOr(null, ['createdByRef', 'node', 'name'], stixObservable) === null
      ? ''
      : {
        label: pathOr(
          null,
          ['createdByRef', 'node', 'name'],
          stixObservable,
        ),
        value: pathOr(null, ['createdByRef', 'node', 'id'], stixObservable),
        relation: pathOr(
          null,
          ['createdByRef', 'relation', 'id'],
          stixObservable,
        ),
      };
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(stixObservable);
    const initialValues = pipe(
      assoc('createdByRef', createdByRef),
      assoc('markingDefinitions', markingDefinitions),
      pick([
        'observable_value',
        'description',
        'createdByRef',
        'killChainPhases',
        'markingDefinitions',
      ]),
    )(stixObservable);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={stixObservableValidation(t)}
        onSubmit={() => true}
      >
        {({ setFieldValue }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              name="observable_value"
              label={t('Observable value')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus
                  context={context}
                  fieldName="observable_value"
                />
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

StixObservableEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  stixObservable: PropTypes.object,
  context: PropTypes.array,
};

const StixObservableEditionOverview = createFragmentContainer(
  StixObservableEditionOverviewComponent,
  {
    stixObservable: graphql`
      fragment StixObservableEditionOverview_stixObservable on StixObservable {
        id
        observable_value
        description
        createdByRef {
          node {
            id
            name
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
)(StixObservableEditionOverview);
