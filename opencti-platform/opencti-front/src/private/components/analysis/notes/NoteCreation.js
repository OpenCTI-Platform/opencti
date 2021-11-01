import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import { ConnectionHandler } from 'relay-runtime';
import {
  compose, evolve, path, pluck,
} from 'ramda';
import * as Yup from 'yup';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogTitle from '@material-ui/core/DialogTitle';
import Grid from '@material-ui/core/Grid';
import DialogActions from '@material-ui/core/DialogActions';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import Fab from '@material-ui/core/Fab';
import { Add, Close } from '@material-ui/icons';
import { commitMutation as CM, createFragmentContainer } from 'react-relay';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import MarkDownField from '../../../../components/MarkDownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { dayStartDate } from '../../../../utils/Time';
import DatePickerField from '../../../../components/DatePickerField';
import TextField from '../../../../components/TextField';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '452px',
    width: '750px',
    maxWidth: '750px',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: '25px 24px 32px 24px',
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  title: {
    float: 'left',
  },
  createButtonContextual: {
    marginTop: -15,
    // bottom: 30,
    // right: 30,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    color: theme.palette.navAlt.backgroundHeaderText,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
});

export const noteCreationMutation = graphql`
  mutation NoteCreationMutation($input: NoteAddInput!) {
    noteAdd(input: $input) {
      id
      ...NoteLine_node
    }
  }
`;

const noteValidation = (t) => Yup.object().shape({
  confidence: Yup.number(),
  created: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  attribute_abstract: Yup.string(),
  content: Yup.string().required(t('This field is required')),
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_notes',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class NoteCreation extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const adaptedValues = evolve(
      {
        createdBy: path(['value']),
        objectMarking: pluck('value'),
        objectLabel: pluck('value'),
      },
      values,
    );
    CM(environmentDarkLight, {
      mutation: noteCreationMutation,
      variables: {
        input: adaptedValues,
      },
      setSubmitting,
      onCompleted: (response) => {
        console.log('NoteCreationDarkLightMutationresponse', response);
        setSubmitting(false);
        resetForm();
        this.handleClose();
      },
      onError: (err) => console.log('NoteCreationDarkLightMutationError', err),
    });
    // commitMutation({
    //   mutation: noteCreationMutation,
    //   variables: {
    //     input: adaptedValues,
    //   },
    //   updater: (store) => {
    //     const payload = store.getRootField('noteAdd');
    //     const newEdge = payload.setLinkedRecord(payload, 'node');
    // Creation of the pagination container.
    //     const container = store.getRoot();
    //     sharedUpdater(
    //       store,
    //       container.getDataID(),
    //       this.props.paginationOptions,
    //       newEdge,
    //     );
    //   },
    //   setSubmitting,
    //   onCompleted: () => {
    //     setSubmitting(false);
    //     resetForm();
    //     this.handleClose();
    //   },
    // });
  }

  onResetClassic() {
    this.handleClose();
  }

  onResetContextual() {
    this.handleClose();
  }

  renderClassic() {
    const { t, classes } = this.props;
    return (
      <div>
        <Fab
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
        <Drawer
          open={this.state.open}
          anchor="right"
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
            >
              <Close fontSize="small" />
            </IconButton>
            <Typography variant="h6">{t('Create a note')}</Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                created: dayStartDate(),
                attribute_abstract: '',
                content: '',
                confidence: 15,
                createdBy: '',
                objectMarking: [],
                objectLabel: [],
              }}
              validationSchema={noteValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onResetClassic.bind(this)}
            >
              {({
                submitForm,
                handleReset,
                isSubmitting,
                setFieldValue,
                values,
              }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field
                    component={DatePickerField}
                    name="created"
                    label={t('Date')}
                    invalidDateMessage={t(
                      'The value must be a date (YYYY-MM-DD)',
                    )}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
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
                  <ConfidenceField
                    name="confidence"
                    label={t('Confidence')}
                    fullWidth={true}
                    containerstyle={{ width: '100%', marginTop: 20 }}
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
          </div>
        </Drawer>
      </div>
    );
  }

  renderContextual() {
    const {
      t, classes, inputValue, display,
    } = this.props;
    return (
      <div style={{ display: display ? 'block' : 'none' }}>
        {/* <Fab
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          aria-label="Add"
          className={classes.createButtonContextual}
        >
          <Add />
        </Fab> */}
        <IconButton
          aria-label="Add"
          edge="end"
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          className={classes.createButtonContextual}
        >
          <Add fontSize="small" />
        </IconButton>
        <Dialog fullWidth={true} maxWidth='md' open={this.state.open} onClose={this.handleClose.bind(this)}>
          <Formik
            enableReinitialize={true}
            initialValues={{
              created: dayStartDate(),
              attribute_abstract: '',
              content: inputValue,
              createdBy: '',
              objectMarking: [],
              objectLabel: [],
            }}
            validationSchema={noteValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
            onReset={this.onResetContextual.bind(this)}
          >
            {({
              submitForm,
              handleReset,
              isSubmitting,
              setFieldValue,
              values,
            }) => (
              <Form style={{ padding: '24px' }}>
              <div>
               <Typography variant="h6" classes={{ root: classes.title }}>
                  {t('New Note')}
              </Typography>
              </div>
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
                    <Grid style={{ marginLeft: 'auto' }} item={true} xs={5}>
                      <div className={classes.buttons}>
                        <Button
                          variant="outlined"
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
        </Dialog>
      </div>
    );
  }

  render() {
    const { contextual } = this.props;
    if (contextual) {
      return this.renderContextual();
    }
    return this.renderClassic();
  }
}

NoteCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  contextual: PropTypes.bool,
  display: PropTypes.bool,
  inputValue: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(NoteCreation);
