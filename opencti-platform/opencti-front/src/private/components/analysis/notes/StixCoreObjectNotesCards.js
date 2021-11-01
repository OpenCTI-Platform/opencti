/* eslint-disable import/no-cycle */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import { createPaginationContainer } from 'react-relay';
import Typography from '@material-ui/core/Typography';
import { Field, Form, Formik } from 'formik';
import Button from '@material-ui/core/Button';
import {
  Add,
  EditOutlined,
  ExpandMoreOutlined,
  RateReviewOutlined,
} from '@material-ui/icons';
import Accordion from '@material-ui/core/Accordion';
import Grid from '@material-ui/core/Grid';
import AccordionSummary from '@material-ui/core/AccordionSummary';
import AccordionDetails from '@material-ui/core/AccordionDetails';
import * as Yup from 'yup';
import { ConnectionHandler } from 'relay-runtime';
import IconButton from '@material-ui/core/IconButton';
import inject18n from '../../../../components/i18n';
import StixCoreObjectOrStixCoreRelationshipNoteCard from './StixCoreObjectOrStixCoreRelationshipNoteCard';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import MarkDownField from '../../../../components/MarkDownField';
import { commitMutation } from '../../../../relay/environment';
import NoteCreation, { noteCreationMutation } from './NoteCreation';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { dayStartDate } from '../../../../utils/Time';
import AddNotes from './AddNotes';

const styles = (theme) => ({
  paper: {
    margin: 0,
    padding: '20px 20px 20px 20px',
    borderRadius: 6,
  },
  heading: {
    display: 'flex',
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  createButton: {
    float: 'left',
    margin: '-15px 0 0 0px',
  },
});

// const noteValidation = (t) => Yup.object().shape({
//   attribute_abstract: Yup.string(),
//   content: Yup.string().required(t('This field is required')),
// });
const noteValidation = (t) => Yup.object().shape({
  confidence: Yup.number(),
  created: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  attribute_abstract: Yup.string(),
  content: Yup.string().required(t('This field is required')),
});

const sharedUpdater = (store, entityId, newEdge) => {
  const entity = store.get(entityId);
  const conn = ConnectionHandler.getConnection(entity, 'Pagination_notes');
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class StixCoreObjectNotesCardsContainer extends Component {
  constructor(props) {
    super(props);
    this.bottomRef = React.createRef();
    this.state = { open: false, search: '' };
  }

  scrollToBottom() {
    setTimeout(() => {
      this.bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }, 400);
  }

  handleToggleWrite() {
    const expanded = !this.state.open;
    this.setState({ open: expanded }, () => {
      if (expanded) {
        this.scrollToBottom();
      }
    });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const { stixCoreObjectId, data } = this.props;
    const defaultMarking = R.pathOr(
      [],
      ['stixCoreObject', 'objectMarking', 'edges'],
      data,
    ).map((n) => n.node.id);
    const adaptedValues = R.pipe(
      R.assoc('objectMarking', [
        ...defaultMarking,
        ...R.pluck('value', values.objectMarking),
      ]),
      R.assoc('objects', [stixCoreObjectId]),
      R.assoc('createdBy', R.pathOr(null, ['createdBy', 'value'], values)),
      R.assoc('objectLabel', R.pluck('value', values.objectLabel)),
    )(values);
    commitMutation({
      mutation: noteCreationMutation,
      variables: {
        input: adaptedValues,
      },
      setSubmitting,
      updater: (store) => {
        const payload = store.getRootField('noteAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node');
        sharedUpdater(store, stixCoreObjectId, newEdge);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  }

  onReset() {
    this.handleToggleWrite();
  }

  render() {
    const {
      t, classes, stixCoreObjectId, marginTop, data,
    } = this.props;
    console.log('NotesCardsData', data);
    const { open } = this.state;
    const notes = R.pathOr([], ['itAsset', 'notes', 'edges'], data);
    return (
      <div style={{ marginTop: marginTop || 40 }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Notes')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          {/* <IconButton
            onClick={this.handleToggleWrite.bind(this)}
            classes={{ root: classes.createButton }}
          > */}
            {/* <EditOutlined fontSize="small" /> */}
            <AddNotes
            stixCoreObjectOrStixCoreRelationshipId={stixCoreObjectId}
            stixCoreObjectOrStixCoreRelationshipNotes={notes}
             />
          {/* </IconButton> */}
        </Security>
        <div className="clearfix" />
        {notes.map((noteEdge) => {
          const note = noteEdge.node;
          return (
            <StixCoreObjectOrStixCoreRelationshipNoteCard
              key={note.id}
              node={note}
              stixCoreObjectOrStixCoreRelationshipId={stixCoreObjectId}
            />
          );
        })}
        {/* <Accordion
          style={{ margin: `${notes.length > 0 ? '30' : '5'}px 0 30px 0` }}
          expanded={open}
          onChange={this.handleToggleWrite.bind(this)}
        >
          <AccordionSummary expandIcon={<ExpandMoreOutlined />} style={{}}>
            <Typography className={classes.heading}>
              <RateReviewOutlined />
              &nbsp;&nbsp;&nbsp;&nbsp;
              <span style={{ fontWeight: 500 }}>{t('Write a note')}</span>
            </Typography>
          </AccordionSummary>
          <AccordionDetails style={{ width: '100%' }}>
            Hello There This is the section for notes and components of notes
            <Formik
              enableReinitialize={true}
              initialValues={{
                created: dayStartDate(),
                attribute_abstract: '',
                content: '',
                createdBy: '',
                objectMarking: [],
                objectLabel: [],
              }}
              validationSchema={noteValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onReset.bind(this)}
            >
              {({
                submitForm,
                handleReset,
                setFieldValue,
                values,
                isSubmitting,
              }) => (
                <Form style={{ width: '100%' }}>
                  <Grid
                    container={true}
                    spacing={3}
                    classes={{ container: classes.gridContainer }}
                  >
                    <Grid item={true} xs={12}>
                      <Field
                        component={MarkDownField}
                        name="content"
                        fullWidth={true}
                        multiline={true}
                        rows="4"
                        style={{ marginTop: 20 }}
                      />
                    </Grid>
                    <Grid item={true} xs={4}>
                      <CreatedByField
                        name="createdBy"
                        style={{ marginTop: 20 }}
                        setFieldValue={setFieldValue}
                      />
                    </Grid>
                    <Grid item={true} xs={4}>
                      <ObjectLabelField
                        name="objectLabel"
                        style={{ marginTop: 20 }}
                        setFieldValue={setFieldValue}
                        values={values.objectLabel}
                      />
                    </Grid>
                    <Grid item={true} xs={4}>
                      <div className={classes.buttons}>
                        <Button
                          variant="contained"
                          onClick={handleReset}
                          disabled={isSubmitting}
                          classes={{ root: classes.button }}
                        >
                          {t('Cancel')}
                        </Button>
                        <Button
                          variant="contained"
                          color="primary"
                          onClick={submitForm}
                          disabled={isSubmitting}
                          classes={{ root: classes.button }}
                        >
                          {t('Create')}
                        </Button>
                      </div>
                    </Grid>
                  </Grid>
                </Form>
              )}
            </Formik>
          </AccordionDetails>
        </Accordion> */}
        {/* <Accordion
          style={{ margin: `${notes.length > 0 ? '30' : '5'}px 0 30px 0` }}
          expanded={open}
          onChange={this.handleToggleWrite.bind(this)}
        >
          <AccordionSummary expandIcon={<ExpandMoreOutlined />} style={{}}>
            <Typography className={classes.heading}>
              <RateReviewOutlined />
              &nbsp;&nbsp;&nbsp;&nbsp;
              <span style={{ fontWeight: 500 }}>{t('Write a note')}</span>
            </Typography>
          </AccordionSummary>
          <AccordionDetails style={{ width: '100%' }}>
            <Formik
              initialValues={{
                attribute_abstract: '',
                content: '',
                createdBy: '',
                objectMarking: [],
                objectLabel: [],
              }}
              validationSchema={noteValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onReset.bind(this)}
            >
              {({
                submitForm,
                handleReset,
                setFieldValue,
                values,
                isSubmitting,
              }) => (
                <Form style={{ width: '100%' }}>
                  <Field
                    component={TextField}
                    name="attribute_abstract"
                    label={t('Abstract')}
                    fullWidth={true}
                  />
                  <Field
                    component={MarkDownField}
                    name="content"
                    label={t('Content')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                    style={{ marginTop: 20 }}
                  />
                  <CreatedByField
                    name="createdBy"
                    style={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                  />
                  <ObjectLabelField
                    name="objectLabel"
                    style={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                    values={values.objectLabel}
                  />
                  <ObjectMarkingField
                    name="objectMarking"
                    style={{ marginTop: 20, width: '100%' }}
                  />
                  <div className={classes.buttons}>
                    <Button
                      variant="contained"
                      onClick={handleReset}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Cancel')}
                    </Button>
                    <Button
                      variant="contained"
                      color="primary"
                      onClick={submitForm}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Create')}
                    </Button>
                  </div>
                </Form>
              )}
            </Formik>
          </AccordionDetails>
        </Accordion> */}
        <div style={{ marginTop: 100 }} />
        <div ref={this.bottomRef} />
      </div>
    );
  }
}

StixCoreObjectNotesCardsContainer.propTypes = {
  stixCoreObjectId: PropTypes.string,
  marginTop: PropTypes.number,
  data: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixCoreObjectNotesCardsQuery = graphql`
  query StixCoreObjectNotesCardsQuery($count: Int!, $id: ID!) {
    ...StixCoreObjectNotesCards_data @arguments(count: $count, id: $id)
  }
`;

const StixCoreObjectNotesCards = createPaginationContainer(
  StixCoreObjectNotesCardsContainer,
  {
    data: graphql`
      fragment StixCoreObjectNotesCards_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
        id: { type: "ID!" }
      ) {
        itAsset(id: $id) {
          id
          notes(first: $count) @connection(key: "Pagination_notes") {
            edges {
              node {
                id
                ...StixCoreObjectOrStixCoreRelationshipNoteCard_node
              }
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.itAsset.notes;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count }, fragmentVariables) {
      return {
        count,
        id: fragmentVariables.id,
      };
    },
    query: stixCoreObjectNotesCardsQuery,
  },
);

// export const stixCoreObjectNotesCardsQuery = graphql`
//   query StixCoreObjectNotesCardsQuery($id: String) {
//     note(id: $id) {
//       objectMarking {
//         edges {
//           node {
//             id
//             definition
//           }
//         }
//       }
//       notes {
//         edges {
//           node {
//             id
//             ...StixCoreObjectOrStixCoreRelationshipNoteCard_node
//           }
//         }
//       }
//     }
//   }
// `;

// const StixCoreObjectNotesCards = createPaginationContainer(
//   StixCoreObjectNotesCardsContainer,
//   {
//     data: graphql`
//       fragment StixCoreObjectNotesCards_data on Query
//       @argumentDefinitions(
//         count: { type: "Int", defaultValue: 25 }
//         id: { type: "String!" }
//       ) {
//         stixCoreObject(id: $id) {
//           id
//           objectMarking {
//             edges {
//               node {
//                 id
//                 definition
//               }
//             }
//           }
//           notes(first: $count) @connection(key: "Pagination_notes") {
//             edges {
//               node {
//                 id
//                 ...StixCoreObjectOrStixCoreRelationshipNoteCard_node
//               }
//             }
//           }
//         }
//       }
//     `,
//   },
//   {
//     direction: 'forward',
//     getConnectionFromProps(props) {
//       return props.data && props.data.stixCoreObjectObject.notes;
//     },
//     getFragmentVariables(prevVars, totalCount) {
//       return {
//         ...prevVars,
//         count: totalCount,
//       };
//     },
//     getVariables(props, { count }, fragmentVariables) {
//       return {
//         count,
//         id: fragmentVariables.id,
//       };
//     },
//     query: stixCoreObjectNotesCardsQuery,
//   },
// );

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectNotesCards);
