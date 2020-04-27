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
import MarkingDefinitionsField from '../form/MarkingDefinitionsField';

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

const stixObjectNoteMutationFieldPatch = graphql`
  mutation StixObjectNoteEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    noteEdit(id: $id) {
      fieldPatch(input: $input) {
        ...StixObjectNoteEditionOverview_note
      }
    }
  }
`;

export const stixObjectNoteEditionOverviewFocus = graphql`
  mutation StixObjectNoteEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    noteEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const stixObjectNoteMutationRelationAdd = graphql`
  mutation StixObjectNoteEditionOverviewRelationAddMutation(
    $id: ID!
    $input: RelationAddInput!
  ) {
    noteEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...StixObjectNoteEditionOverview_note
        }
      }
    }
  }
`;

const stixObjectNoteMutationRelationDelete = graphql`
  mutation StixObjectNoteEditionOverviewRelationDeleteMutation(
    $id: ID!
    $relationId: ID!
  ) {
    noteEdit(id: $id) {
      relationDelete(relationId: $relationId) {
        ...StixObjectNoteEditionOverview_note
      }
    }
  }
`;

const noteValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  content: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class StixObjectNoteEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: stixObjectNoteEditionOverviewFocus,
      variables: {
        id: this.props.note.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    noteValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: stixObjectNoteMutationFieldPatch,
          variables: { id: this.props.note.id, input: { key: name, value } },
        });
      })
      .catch(() => false);
  }

  handleChangeMarkingDefinitions(name, values) {
    const { note } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(note);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: stixObjectNoteMutationRelationAdd,
        variables: {
          id: this.props.note.id,
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
        mutation: stixObjectNoteMutationRelationDelete,
        variables: {
          id: this.props.note.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  render() {
    const { t, note, context } = this.props;
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(note);
    const initialValues = pipe(
      assoc('markingDefinitions', markingDefinitions),
      pick(['name', 'content', 'markingDefinitions']),
    )(note);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={noteValidation(t)}
        onSubmit={() => true}
      >
        {() => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              name="name"
              label={t('Title')}
              fullWidth={true}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="name" />
              }
            />
            <Field
              component={TextField}
              name="content"
              label={t('Content')}
              fullWidth={true}
              multiline={true}
              rows="6"
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="content" />
              }
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

StixObjectNoteEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  note: PropTypes.object,
  context: PropTypes.array,
};

const StixObjectNoteEditionOverview = createFragmentContainer(
  StixObjectNoteEditionOverviewComponent,
  {
    note: graphql`
      fragment StixObjectNoteEditionOverview_note on Note {
        id
        name
        content
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
  withStyles(styles),
)(StixObjectNoteEditionOverview);
