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
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';

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

const stixCyberObservableMutationFieldPatch = graphql`
  mutation StixCyberObservableEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    stixCyberObservableEdit(id: $id) {
      fieldPatch(input: $input) {
        ...StixCyberObservableEditionOverview_stixCyberObservable
      }
    }
  }
`;

export const stixCyberObservableEditionOverviewFocus = graphql`
  mutation StixCyberObservableEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    stixCyberObservableEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const stixCyberObservableMutationRelationAdd = graphql`
  mutation StixCyberObservableEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    stixCyberObservableEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...StixCyberObservableEditionOverview_stixCyberObservable
        }
      }
    }
  }
`;

const stixCyberObservableMutationRelationDelete = graphql`
  mutation StixCyberObservableEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: String!
    $relationship_type: String!
  ) {
    stixCyberObservableEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...StixCyberObservableEditionOverview_stixCyberObservable
      }
    }
  }
`;

const stixCyberObservableValidation = (t) => Yup.object().shape({
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class StixCyberObservableEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: stixCyberObservableEditionOverviewFocus,
      variables: {
        id: this.props.stixCyberObservable.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    stixCyberObservableValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: stixCyberObservableMutationFieldPatch,
          variables: {
            id: this.props.stixCyberObservable.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedBy(name, value) {
    const { stixCyberObservable } = this.props;
    const currentCreatedBy = {
      label: pathOr(null, ['createdBy', 'node', 'name'], stixCyberObservable),
      value: pathOr(null, ['createdBy', 'node', 'id'], stixCyberObservable),
      relation: pathOr(
        null,
        ['createdBy', 'relation', 'id'],
        stixCyberObservable,
      ),
    };

    if (currentCreatedBy.value === null) {
      commitMutation({
        mutation: stixCyberObservableMutationRelationAdd,
        variables: {
          id: this.props.stixCyberObservable.id,
          input: {
            toId: value.value,
            relationship_type: 'created-by',
          },
        },
      });
    } else if (currentCreatedBy.value !== value.value) {
      commitMutation({
        mutation: stixCyberObservableMutationRelationDelete,
        variables: {
          id: this.props.stixCyberObservable.id,
          relationId: currentCreatedBy.relation,
        },
      });
      if (value.value) {
        commitMutation({
          mutation: stixCyberObservableMutationRelationAdd,
          variables: {
            id: this.props.stixCyberObservable.id,
            input: {
              toId: value.value,
              relationship_type: 'created-by',
            },
          },
        });
      }
    }
  }

  handleChangeMarkingDefinitions(name, values) {
    const { stixCyberObservable } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(stixCyberObservable);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: stixCyberObservableMutationRelationAdd,
        variables: {
          id: this.props.stixCyberObservable.id,
          input: {
            toId: head(added).value,
            relationship_type: 'object-marking',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: stixCyberObservableMutationRelationDelete,
        variables: {
          id: this.props.stixCyberObservable.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  render() {
    const { t, stixCyberObservable, context } = this.props;
    const createdBy = pathOr(null, ['createdBy', 'node', 'name'], stixCyberObservable) === null
      ? ''
      : {
        label: pathOr(
          null,
          ['createdBy', 'node', 'name'],
          stixCyberObservable,
        ),
        value: pathOr(
          null,
          ['createdBy', 'node', 'id'],
          stixCyberObservable,
        ),
        relation: pathOr(
          null,
          ['createdBy', 'relation', 'id'],
          stixCyberObservable,
        ),
      };
    const markingDefinitions = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(stixCyberObservable);
    const initialValues = pipe(
      assoc('createdBy', createdBy),
      assoc('markingDefinitions', markingDefinitions),
      pick([
        'observable_value',
        'description',
        'createdBy',
        'killChainPhases',
        'markingDefinitions',
      ]),
    )(stixCyberObservable);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={stixCyberObservableValidation(t)}
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
              onChange={this.handleChangeMarkingDefinitions.bind(this)}
            />
          </Form>
        )}
      </Formik>
    );
  }
}

StixCyberObservableEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  stixCyberObservable: PropTypes.object,
  context: PropTypes.array,
};

const StixCyberObservableEditionOverview = createFragmentContainer(
  StixCyberObservableEditionOverviewComponent,
  {
    stixCyberObservable: graphql`
      fragment StixCyberObservableEditionOverview_stixCyberObservable on StixCyberObservable {
        id
        observable_value
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
              definition
              definition_type
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
)(StixCyberObservableEditionOverview);
