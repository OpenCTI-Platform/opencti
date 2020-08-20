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
import ObjectMarkingField from '../form/ObjectMarkingField';

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

const stixCoreObjectNoteMutationFieldPatch = graphql`
  mutation StixCoreObjectNoteEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    noteEdit(id: $id) {
      fieldPatch(input: $input) {
        ...StixCoreObjectNoteEditionOverview_note
      }
    }
  }
`;

export const stixCoreObjectNoteEditionOverviewFocus = graphql`
  mutation StixCoreObjectNoteEditionOverviewFocusMutation(
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

const stixCoreObjectNoteMutationRelationAdd = graphql`
  mutation StixCoreObjectNoteEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput!
  ) {
    noteEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...StixCoreObjectNoteEditionOverview_note
        }
      }
    }
  }
`;

const stixCoreObjectNoteMutationRelationDelete = graphql`
  mutation StixCoreObjectNoteEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: String!
    $relationship_type: String!
  ) {
    noteEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...StixCoreObjectNoteEditionOverview_note
      }
    }
  }
`;

const noteValidation = (t) => Yup.object().shape({
  attribute_abstract: Yup.string().required(t('This field is required')),
  content: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class StixCoreObjectNoteEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: stixCoreObjectNoteEditionOverviewFocus,
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
          mutation: stixCoreObjectNoteMutationFieldPatch,
          variables: { id: this.props.note.id, input: { key: name, value } },
        });
      })
      .catch(() => false);
  }

  handleChangeObjectMarking(name, values) {
    const { note } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(note);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: stixCoreObjectNoteMutationRelationAdd,
        variables: {
          id: this.props.note.id,
          input: {
            toId: head(added).value,
            relationship_type: 'object-marking',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: stixCoreObjectNoteMutationRelationDelete,
        variables: {
          id: this.props.note.id,
          toId: head(removed).value,
          relationship_type: 'object-marking',
        },
      });
    }
  }

  render() {
    const { t, note, context } = this.props;
    const markingDefinitions = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
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
              name="attribute_abstract"
              label={t('Abstract')}
              fullWidth={true}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus
                  context={context}
                  fieldName="attribute_abstract"
                />
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
            <ObjectMarkingField
              name="objectMarking"
              style={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="objectMarking"
                />
              }
              onChange={this.handleChangeObjectMarking.bind(this)}
            />
          </Form>
        )}
      </Formik>
    );
  }
}

StixCoreObjectNoteEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  note: PropTypes.object,
  context: PropTypes.array,
};

const StixCoreObjectNoteEditionOverview = createFragmentContainer(
  StixCoreObjectNoteEditionOverviewComponent,
  {
    note: graphql`
      fragment StixCoreObjectNoteEditionOverview_note on Note {
        id
        attribute_abstract
        content
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
  withStyles(styles),
)(StixCoreObjectNoteEditionOverview);
