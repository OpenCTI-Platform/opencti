/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { commitMutation as CM, createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import {
  assoc,
  compose,
  map,
  pathOr,
  pipe,
  pick,
} from 'ramda';
import * as Yup from 'yup';
import Button from '@material-ui/core/Button';
import Grid from '@material-ui/core/Grid';
import Badge from '@material-ui/core/Badge';
import Avatar from '@material-ui/core/Avatar';
import Typography from '@material-ui/core/Typography';
import TextField from '../../../../components/TextField';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import MarkDownField from '../../../../components/MarkDownField';
import CyioCoreObjectLabelsView from '../../common/stix_core_objects/CyioCoreObjectLabelsView';
// import { SubscriptionFocus } from '../../../../components/Subscription';

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
  buttonPopover: {
    marginTop: '25px',
    textTransform: 'capitalize',
  },
});

export const cyioNoteMutationFieldPatch = graphql`
  mutation CyioNoteEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    editCyioNote(id: $id, input: $input) {
        ...CyioNoteEditionOverview_note
        # ...Note_note
    }
  }
`;

export const cyioNoteEditionOverviewFocus = graphql`
  mutation CyioNoteEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    noteEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

// const cyioNoteMutationRelationAdd = graphql`
//   mutation CyioNoteEditionOverviewRelationAddMutation(
//     $id: ID!
//     $input: StixMetaRelationshipAddInput
//   ) {
//     noteEdit(id: $id) {
//       relationAdd(input: $input) {
//         from {
//           ...CyioNoteEditionOverview_note
//         }
//       }
//     }
//   }
// `;

// const cyioNoteMutationRelationDelete = graphql`
//   mutation CyioNoteEditionOverviewRelationDeleteMutation(
//     $id: ID!
//     $toId: String!
//     $relationship_type: String!
//   ) {
//     noteEdit(id: $id) {
//       relationDelete(toId: $toId, relationship_type: $relationship_type) {
//         ...CyioNoteEditionOverview_note
//       }
//     }
//   }
// `;

const cyioNoteValidation = (t) => Yup.object().shape({
  attribute_abstract: Yup.string(),
  content: Yup.string().required(t('This field is required')),
  // created: Yup.date()
  //   .typeError(t('The value must be a date (YYYY-MM-DD)'))
  //   .required(t('This field is required')),
  // confidence: Yup.number(),
});

class CyioNoteEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: cyioNoteEditionOverviewFocus,
      variables: {
        id: this.props.note.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    cyioNoteValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: cyioNoteMutationFieldPatch,
          variables: { id: this.props.note.id, input: { key: name, value } },
        });
      })
      .catch(() => false);
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    CM(environmentDarkLight, {
      mutation: cyioNoteMutationFieldPatch,
      variables: {
        id: this.props.note.id,
        input: [
          { key: 'content', value: values.content },
          { key: 'authors', value: values.authors },
          // { key: 'labels', value: values.labels },
          // { key: 'description', value: values.description },
        ],
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.props.handleClose();
      },
      // onError: (err) => console.log('CyioNoteEditionDarkLightMutationError', err),
    });
  }

  onReset() {
    this.props.handleClose();
  }

  // handleChangeCreatedBy(name, value) {
  //   commitMutation({
  //     mutation: cyioNoteMutationFieldPatch,
  //     variables: {
  //       id: this.props.note.id,
  //       input: { key: 'createdBy', value: value.value || '' },
  //     },
  //   });
  // }

  render() {
    const {
      t,
      note,
      classes,
    } = this.props;
    // const createdBy = pathOr(null, ['createdBy', 'name'], note) === null
    //   ? ''
    //   : {
    //     label: pathOr(null, ['createdBy', 'name'], note),
    //     value: pathOr(null, ['createdBy', 'id'], note),
    //   };
    // const objectMarking = pipe(
    //   pathOr([], ['objectMarking', 'edges']),
    //   map((n) => ({
    //     label: n.node.definition,
    //     value: n.node.id,
    //   })),
    // )(note);
    const initialValues = pipe(
      assoc('content', note.content),
      assoc('authors', note.authors),
      assoc('labels', note.labels),
      pick([
        'content',
        'authors',
        'labels',
      ]),
    )(note);
    return (
      <Formik
        // enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={cyioNoteValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
        onReset={this.onReset.bind(this)}
      >
        {({
          submitForm,
          handleReset,
          isSubmitting,
        }) => (
          <div>
            <Form style={{ margin: '20px 0 0px 0' }}>
              <Field
                component={MarkDownField}
                name="content"
                // label={t('Content')}
                fullWidth={true}
                multiline={true}
                rows="4"
                style={{ marginTop: 20, marginBottom: 20 }}
              />
              <CyioCoreObjectLabelsView
                name="labels"
                labels={note.labels}
                typename={note.__typename}
                id={note.id}
              />
              <div style={{ display: 'grid', gridTemplateColumns: '50% 1fr', marginTop: '20px' }}>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                    style={{ float: 'left' }}
                  >
                    {t('Author')}
                  </Typography>
                  <div className="clearfix" />
                  <Field
                    component={TextField}
                    name="authors"
                    // label={t('Abstract')}
                    fullWidth={true}
                  />
                </div>
                <div style={{ textAlign: 'right' }}>
                  <Button
                    onClick={handleReset}
                    disabled={isSubmitting}
                    variant="outlined"
                    size="small"
                    classes={{ root: classes.buttonPopover }}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    onClick={submitForm}
                    color="primary"
                    disabled={isSubmitting}
                    variant="contained"
                    size="small"
                    style={{ marginLeft: '15px' }}
                    classes={{ root: classes.buttonPopover }}
                  >
                    {t('Update')}
                  </Button>
                </div>
              </div>
            </Form>
          </div>
        )}
      </Formik>
    );
  }
}

CyioNoteEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  note: PropTypes.object,
  context: PropTypes.array,
};

const CyioNoteEditionOverview = createFragmentContainer(
  CyioNoteEditionOverviewComponent,
  {
    note: graphql`
      fragment CyioNoteEditionOverview_note on CyioNote {
        __typename
        id
        created
        modified
        abstract
        content
        authors
        labels {
            id
            name
            color
            description
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(CyioNoteEditionOverview);
