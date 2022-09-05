import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import withStyles from '@mui/styles/withStyles';
import * as Yup from 'yup';
import * as R from 'ramda';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import MarkDownField from '../../../../components/MarkDownField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ConfidenceField from '../../common/form/ConfidenceField';
import TextField from '../../../../components/TextField';
import {
  convertCreatedBy, convertOrganizations,
  convertMarkings,
  convertStatus,
} from '../../../../utils/Edition';
import StatusField from '../../common/form/StatusField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { buildDate } from '../../../../utils/Time';
import Security, { KNOWLEDGE_KNUPDATE_KNORGARESTRICT } from '../../../../utils/Security';
import ObjectOrganizationField from '../../common/form/ObjectOrganizationField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

const styles = (theme) => ({
  restrictions: {
    padding: 10,
    marginBottom: 20,
    backgroundColor: theme.palette.background.nav,
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'hidden',
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
    $input: [EditInput]!
  ) {
    noteEdit(id: $id) {
      fieldPatch(input: $input) {
        ...NoteEditionOverview_note
        ...Note_note
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
    $toId: StixRef!
    $relationship_type: String!
  ) {
    noteEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...NoteEditionOverview_note
      }
    }
  }
`;

const noteMutationGroupAdd = graphql`
  mutation NoteEditionOverviewGroupAddMutation($id: ID!, $organizationId: ID!) {
    stixCoreObjectEdit(id: $id) {
      restrictionOrganizationAdd(organizationId: $organizationId) {
        ...NoteEditionOverview_note
      }
    }
  }
`;

const noteMutationGroupDelete = graphql`
  mutation NoteEditionOverviewGroupDeleteMutation($id: ID!, $organizationId: ID!) {
    stixCoreObjectEdit(id: $id) {
      restrictionOrganizationDelete(organizationId: $organizationId) {
        ...NoteEditionOverview_note
      }
    }
  }
`;

const noteValidation = (t) => Yup.object().shape({
  attribute_abstract: Yup.string().nullable(),
  content: Yup.string().required(t('This field is required')),
  created: Yup.date()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .required(t('This field is required')),
  confidence: Yup.number(),
  x_opencti_workflow_id: Yup.object(),
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
    let finalValue = value;
    if (name === 'x_opencti_workflow_id') {
      finalValue = value.value;
    }
    noteValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: noteMutationFieldPatch,
          variables: {
            id: this.props.note.id,
            input: { key: name, value: finalValue ?? '' },
          },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedBy(name, value) {
    commitMutation({
      mutation: noteMutationFieldPatch,
      variables: {
        id: this.props.note.id,
        input: { key: 'createdBy', value: value.value || '' },
      },
    });
  }

  handleChangeObjectMarking(name, values) {
    const { note } = this.props;
    const currentMarkingDefinitions = R.pipe(
      R.pathOr([], ['objectMarking', 'edges']),
      R.map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(note);
    const added = R.difference(values, currentMarkingDefinitions);
    const removed = R.difference(currentMarkingDefinitions, values);
    if (added.length > 0) {
      commitMutation({
        mutation: noteMutationRelationAdd,
        variables: {
          id: this.props.note.id,
          input: {
            toId: R.head(added).value,
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
          toId: R.head(removed).value,
          relationship_type: 'object-marking',
        },
      });
    }
  }

  handleChangeObjectOrganization(name, values) {
    const { note } = this.props;
    const currentValues = R.pipe(
      R.pathOr([], ['objectOrganization', 'edges']),
      R.map((n) => ({
        label: n.node.name,
        value: n.node.id,
      })),
    )(note);
    const added = R.difference(values, currentValues);
    const removed = R.difference(currentValues, values);
    if (added.length > 0) {
      commitMutation({
        mutation: noteMutationGroupAdd,
        variables: {
          id: this.props.note.id,
          organizationId: R.head(added).value,
        },
      });
    }
    if (removed.length > 0) {
      commitMutation({
        mutation: noteMutationGroupDelete,
        variables: {
          id: this.props.note.id,
          organizationId: R.head(removed).value,
        },
      });
    }
  }

  render() {
    const { t, note, classes, context } = this.props;
    const createdBy = convertCreatedBy(note);
    const objectMarking = convertMarkings(note);
    const objectOrganization = convertOrganizations(note);
    const status = convertStatus(t, note);
    const initialValues = R.pipe(
      R.assoc('createdBy', createdBy),
      R.assoc('objectMarking', objectMarking),
      R.assoc('objectOrganization', objectOrganization),
      R.assoc('x_opencti_workflow_id', status),
      R.assoc('created', buildDate(note.created)),
      R.pick([
        'attribute_abstract',
        'created',
        'content',
        'confidence',
        'createdBy',
        'objectOrganization',
        'objectMarking',
        'x_opencti_workflow_id',
      ]),
    )(note);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={noteValidation(t)}
      >
        {({ setFieldValue }) => (
          <div>
            <Form style={{ margin: '0px 0 20px 0' }}>
              <Security needs={[KNOWLEDGE_KNUPDATE_KNORGARESTRICT]}>
                <div className={classes.restrictions}>
                  <ObjectOrganizationField name="objectOrganization" style={{ width: '100%' }}
                                    helpertext={<SubscriptionFocus context={context} fieldname="objectOrganization"/>}
                                    onChange={this.handleChangeObjectOrganization.bind(this)}
                  />
                </div>
              </Security>
              <Field
                component={DateTimePickerField}
                name="created"
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                TextFieldProps={{
                  label: t('Publication date'),
                  variant: 'standard',
                  fullWidth: true,
                  helperText: (
                    <SubscriptionFocus context={context} fieldName="created" />
                  ),
                }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="attribute_abstract"
                label={t('Abstract')}
                fullWidth={true}
                style={{ marginTop: 20 }}
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
                component={MarkDownField}
                name="content"
                label={t('Content')}
                fullWidth={true}
                multiline={true}
                rows="4"
                style={{ marginTop: 20 }}
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus context={context} fieldName="content" />
                }
              />
              <ConfidenceField
                name="confidence"
                onFocus={this.handleChangeFocus.bind(this)}
                onChange={this.handleSubmitField.bind(this)}
                label={t('Confidence')}
                fullWidth={true}
                containerStyle={fieldSpacingContainerStyle}
                editContext={context}
                variant="edit"
              />
              {note.workflowEnabled && (
                <StatusField
                  name="x_opencti_workflow_id"
                  type="Note"
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
        created
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
        objectOrganization {
          edges {
            node {
              id
              name
            }
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

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(NoteEditionOverview);
