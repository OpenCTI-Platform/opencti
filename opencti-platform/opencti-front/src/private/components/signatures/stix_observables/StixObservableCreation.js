import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import Fab from '@material-ui/core/Fab';
import { Add, Close } from '@material-ui/icons';
import {
  compose, pluck, evolve, path,
} from 'ramda';
import * as Yup from 'yup';
import graphql from 'babel-plugin-relay/macro';
import { ConnectionHandler } from 'relay-runtime';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContent from '@material-ui/core/DialogContent';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SwitchField from '../../../../components/SwitchField';
import CreatedByRefField from '../../common/form/CreatedByRefField';
import TagsField from '../../common/form/TagsField';
import MarkingDefinitionsField from '../../common/form/MarkingDefinitionsField';
import TypesField from '../TypesField';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 280,
    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
  createButtonExports: {
    position: 'fixed',
    bottom: 30,
    right: 590,
    transition: theme.transitions.create('right', {
      easing: theme.transitions.easing.easeOut,
      duration: theme.transitions.duration.leavingScreen,
    }),
  },
  createButtonContextual: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
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
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
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

const stixObservableMutation = graphql`
  mutation StixObservableCreationMutation($input: StixObservableAddInput!) {
    stixObservableAdd(input: $input) {
      ...StixObservableLine_node
    }
  }
`;

const stixObservableValidation = (t) => Yup.object().shape({
  type: Yup.string().required(t('This field is required')),
  observable_value: Yup.string().required(t('This field is required')),
  description: Yup.string(),
  createIndicator: Yup.boolean(),
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_stixObservables',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class StixObservableCreation extends Component {
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
        createdByRef: path(['value']),
        markingDefinitions: pluck('value'),
        tags: pluck('value'),
      },
      values,
    );
    commitMutation({
      mutation: stixObservableMutation,
      variables: {
        input: adaptedValues,
      },
      updater: (store) => {
        const payload = store.getRootField('stixObservableAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node'); // Creation of the pagination container.
        const container = store.getRoot();
        sharedUpdater(
          store,
          container.getDataID(),
          this.props.paginationOptions,
          newEdge,
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
      },
    });
  }

  onReset() {
    this.handleClose();
  }

  renderClassic() {
    const { t, classes, openExports } = this.props;
    return (
      <div>
        <Fab
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          aria-label="Add"
          className={
            openExports ? classes.createButtonExports : classes.createButton
          }
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
            <Typography variant="h6">{t('Create an observable')}</Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                type: '',
                observable_value: '',
                description: '',
                createdByRef: '',
                markingDefinitions: [],
                tags: [],
                createIndicator: false,
              }}
              validationSchema={stixObservableValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onReset.bind(this)}
            >
              {({
                submitForm,
                handleReset,
                isSubmitting,
                setFieldValue,
                values,
              }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <TypesField
                    name="type"
                    label={t('Observable type')}
                    containerstyle={{ width: '100%' }}
                  />
                  <Field
                    component={TextField}
                    name="observable_value"
                    label={t('Observable value')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    name="description"
                    label={t('Description')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                    style={{ marginTop: 20 }}
                  />
                  <CreatedByRefField
                    name="createdByRef"
                    style={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                  />
                  <TagsField
                    name="tags"
                    style={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                    values={values.tags}
                  />
                  <MarkingDefinitionsField
                    name="markingDefinitions"
                    style={{ marginTop: 20, width: '100%' }}
                  />
                  <Field
                    component={SwitchField}
                    type="checkbox"
                    name="createIndicator"
                    label={t('Create an indicator from this observable')}
                    containerstyle={{ marginTop: 20 }}
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
        <Fab
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          aria-label="Add"
          className={classes.createButtonContextual}
        >
          <Add />
        </Fab>
        <Formik
          initialValues={{
            type: '',
            observable_value: inputValue,
            description: '',
            createdByRef: '',
            markingDefinitions: [],
          }}
          validationSchema={stixObservableValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
          onReset={this.onReset.bind(this)}
        >
          {({
            submitForm,
            handleReset,
            isSubmitting,
            setFieldValue,
            values,
          }) => (
            <Form>
              <Dialog
                open={this.state.open}
                onClose={this.handleClose.bind(this)}
                fullWidth={true}
              >
                <DialogTitle>{t('Create an entity')}</DialogTitle>
                <DialogContent>
                  <TypesField
                    name="type"
                    label={t('Observable type')}
                    containerstyle={{ width: '100%' }}
                  />
                  <Field
                    component={TextField}
                    name="observable_value"
                    label={t('Observable value')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    name="description"
                    label={t('Description')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                    style={{ marginTop: 20 }}
                  />
                  <CreatedByRefField
                    name="createdByRef"
                    style={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                  />
                  <TagsField
                    name="tags"
                    style={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                    values={values.tags}
                  />
                  <MarkingDefinitionsField
                    name="markingDefinitions"
                    style={{ marginTop: 20, width: '100%' }}
                  />
                </DialogContent>
                <DialogActions>
                  <Button onClick={handleReset} disabled={isSubmitting}>
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="primary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                  >
                    {t('Create')}
                  </Button>
                </DialogActions>
              </Dialog>
            </Form>
          )}
        </Formik>
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

StixObservableCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  contextual: PropTypes.bool,
  display: PropTypes.bool,
  inputValue: PropTypes.string,
  openExports: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(StixObservableCreation);
