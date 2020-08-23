import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import MenuItem from '@material-ui/core/MenuItem';
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
import { dateFormat } from '../../../../utils/Time';
import { QueryRenderer, commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import DatePickerField from '../../../../components/DatePickerField';
import { attributesQuery } from '../../settings/attributes/AttributesLines';
import Loader from '../../../../components/Loader';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ConfidenceField from '../../common/form/ConfidenceField';

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

export const noteMutationFieldPatch = graphql`
  mutation NoteEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    noteEdit(id: $id) {
      fieldPatch(input: $input) {
        ...NoteEditionOverview_note
      }
    }
  }
`;

export const noteEditionOverviewFocus = graphql`
  mutation NoteEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    noteEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const noteMutationRelationAdd = graphql`
  mutation NoteEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput
  ) {
    noteEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...NoteEditionOverview_note
        }
      }
    }
  }
`;

const noteMutationRelationDelete = graphql`
  mutation NoteEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: String!
    $relationship_type: String!
  ) {
    noteEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...NoteEditionOverview_note
      }
    }
  }
`;

const noteValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  published: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  note_types: Yup.array().required(t('This field is required')),
  description: Yup.string(),
  confidence: Yup.number(),
  x_opencti_note_status: Yup.number(),
});

class NoteEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: noteEditionOverviewFocus,
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
          mutation: noteMutationFieldPatch,
          variables: { id: this.props.note.id, input: { key: name, value } },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedBy(name, value) {
    const { note } = this.props;
    const currentCreatedBy = {
      label: pathOr(null, ['createdBy', 'name'], note),
      value: pathOr(null, ['createdBy', 'id'], note),
    };

    if (currentCreatedBy.value === null) {
      commitMutation({
        mutation: noteMutationRelationAdd,
        variables: {
          id: this.props.note.id,
          input: {
            toId: value.value,
            relationship_type: 'created-by',
          },
        },
      });
    } else if (currentCreatedBy.value !== value.value) {
      commitMutation({
        mutation: noteMutationRelationDelete,
        variables: {
          id: this.props.note.id,
          toId: currentCreatedBy.value,
          relationship_type: 'created-by',
        },
      });
      if (value.value) {
        commitMutation({
          mutation: noteMutationRelationAdd,
          variables: {
            id: this.props.note.id,
            input: {
              toId: value.value,
              relationship_type: 'created-by',
            },
          },
        });
      }
    }
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
        mutation: noteMutationRelationAdd,
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
        mutation: noteMutationRelationDelete,
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
    const createdBy = pathOr(null, ['createdBy', 'name'], note) === null
      ? ''
      : {
        label: pathOr(null, ['createdBy', 'name'], note),
        value: pathOr(null, ['createdBy', 'id'], note),
      };
    const objectMarking = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(note);
    const initialValues = pipe(
      assoc('createdBy', createdBy),
      assoc('objectMarking', objectMarking),
      assoc('published', dateFormat(note.published)),
      pick([
        'name',
        'published',
        'description',
        'note_types',
        'createdBy',
        'objectMarking',
        'confidence',
        'x_opencti_note_status',
      ]),
    )(note);
    return (
      <div>
        <QueryRenderer
          query={attributesQuery}
          variables={{ type: 'note_types' }}
          render={({ props }) => {
            if (props && props.attributes) {
              const noteTypesEdges = props.attributes.edges;
              return (
                <Formik
                  enableReinitialize={true}
                  initialValues={initialValues}
                  validationSchema={noteValidation(t)}
                >
                  {({ setFieldValue }) => (
                    <div>
                      <Form style={{ margin: '20px 0 20px 0' }}>
                        <Field
                          component={TextField}
                          name="name"
                          label={t('Name')}
                          fullWidth={true}
                          onFocus={this.handleChangeFocus.bind(this)}
                          onSubmit={this.handleSubmitField.bind(this)}
                          helperText={
                            <SubscriptionFocus
                              context={context}
                              fieldName="name"
                            />
                          }
                        />
                        <Field
                          component={SelectField}
                          name="note_types"
                          onFocus={this.handleChangeFocus.bind(this)}
                          onChange={this.handleSubmitField.bind(this)}
                          label={t('Note types')}
                          fullWidth={true}
                          multiple={true}
                          containerstyle={{ marginTop: 20, width: '100%' }}
                          helpertext={
                            <SubscriptionFocus
                              context={context}
                              fieldName="note_types"
                            />
                          }
                        >
                          {noteTypesEdges.map((noteTypeEdge) => (
                            <MenuItem
                              key={noteTypeEdge.node.value}
                              value={noteTypeEdge.node.value}
                            >
                              {noteTypeEdge.node.value}
                            </MenuItem>
                          ))}
                        </Field>
                        <Field
                          component={DatePickerField}
                          name="published"
                          label={t('Publication date')}
                          invalidDateMessage={t(
                            'The value must be a date (YYYY-MM-DD)',
                          )}
                          fullWidth={true}
                          style={{ marginTop: 20 }}
                          onFocus={this.handleChangeFocus.bind(this)}
                          onSubmit={this.handleSubmitField.bind(this)}
                          helperText={
                            <SubscriptionFocus
                              context={context}
                              fieldName="published"
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
                            <SubscriptionFocus
                              context={context}
                              fieldName="description"
                            />
                          }
                        />
                        <Field
                          component={SelectField}
                          name="x_opencti_note_status"
                          onFocus={this.handleChangeFocus.bind(this)}
                          onChange={this.handleSubmitField.bind(this)}
                          label={t('Processing status')}
                          fullWidth={true}
                          containerstyle={{ width: '100%', marginTop: 20 }}
                          helpertext={
                            <SubscriptionFocus
                              context={context}
                              fieldName="x_opencti_note_status"
                            />
                          }
                        >
                          <MenuItem key="0" value="0">
                            {t('note_status_0')}
                          </MenuItem>
                          <MenuItem key="1" value="1">
                            {t('note_status_1')}
                          </MenuItem>
                          <MenuItem key="2" value="2">
                            {t('note_status_2')}
                          </MenuItem>
                          <MenuItem key="3" value="3">
                            {t('note_status_3')}
                          </MenuItem>
                        </Field>
                        <ConfidenceField
                          name="confidence"
                          onFocus={this.handleChangeFocus.bind(this)}
                          onChange={this.handleSubmitField.bind(this)}
                          label={t('Confidence')}
                          fullWidth={true}
                          containerstyle={{ width: '100%', marginTop: 20 }}
                          editContext={context}
                          variant="edit"
                        />
                        <CreatedByField
                          name="createdBy"
                          style={{ marginTop: 20, width: '100%' }}
                          setFieldValue={setFieldValue}
                          helpertext={
                            <SubscriptionFocus
                              context={context}
                              fieldName="createdBy"
                            />
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
                      </Form>
                    </div>
                  )}
                </Formik>
              );
            }
            return <Loader variant="inElement" />;
          }}
        />
      </div>
    );
  }
}

NoteEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  note: PropTypes.object,
  context: PropTypes.array,
};

const NoteEditionOverview = createFragmentContainer(
  NoteEditionOverviewComponent,
  {
    note: graphql`
      fragment NoteEditionOverview_note on Note {
        id
        attribute_abstract
        content
        confidence
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
)(NoteEditionOverview);
