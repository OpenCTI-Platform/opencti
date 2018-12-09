import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { commitMutation } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import Fab from '@material-ui/core/Fab';
import { Add, Close } from '@material-ui/icons';
import { compose, head } from 'ramda';
import * as Yup from 'yup';
import graphql from 'babel-plugin-relay/macro';
import { ConnectionHandler } from 'relay-runtime';
import inject18n from '../../../components/i18n';
import environment from '../../../relay/environment';
import TextField from '../../../components/TextField';

const styles = theme => ({
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
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing.unit * 2,
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

const markingDefinitionMutation = graphql`
    mutation MarkingDefinitionCreationMutation($input: MarkingDefinitionAddInput!) {
        markingDefinitionAdd(input: $input) {
            ...MarkingDefinitionLine_markingDefinition
        }
    }
`;

const markingDefinitionValidation = t => Yup.object().shape({
  definition_type: Yup.string()
    .required(t('This field is required')),
  definition: Yup.string()
    .required(t('This field is required')),
  color: Yup.string()
    .required(t('This field is required')),
  level: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number'))
    .required(t('This field is required')),
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_markingDefinitions',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class MarkingDefinitionCreation extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, markingDefinitions: [] };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  onSubmit(values, { setSubmitting, resetForm, setErrors }) {
    values.level = parseInt(values.level, 10);
    commitMutation(environment, {
      mutation: markingDefinitionMutation,
      variables: {
        input: values,
      },
      updater: (store) => {
        const payload = store.getRootField('markingDefinitionAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node'); // Creation of the pagination container.
        const container = store.getRoot();
        sharedUpdater(store, container.getDataID(), this.props.paginationOptions, newEdge);
      },
      /* optimisticUpdater: (store) => {
        const root = store.getRoot();
        const user = root.getLinkedRecord('me');
        const id = Math.floor(Math.random() * 999999) + 100000;
        const node = store.create(`client:newMarkingDefinition:V${id}`, 'MarkingDefinition');
        node.setValue(`client:newMarkingDefinition:V${id}`, 'id');
        node.setValue('YOOOOOOOOOOOOOOOOOOOO', 'name');
        node.setValue(values.description, 'description');
        const newEdge = store.create(`client:newEdge:V${id}`, 'markingDefinitionEdge');
        newEdge.setLinkedRecord(node, 'node');
        sharedUpdater(store, user.getDataID(), this.props.orderBy, newEdge);
      }, */
      onCompleted: (response, errors) => {
        setSubmitting(false);
        if (errors) {
          const error = this.props.t(head(errors).message);
          setErrors({ name: error }); // Push the error in the name field
        } else {
          resetForm();
          this.handleClose();
        }
      },
    });
  }

  onReset() {
    this.handleClose();
  }

  render() {
    const { t, classes } = this.props;
    return (
      <div>
        <Fab onClick={this.handleOpen.bind(this)}
             color='secondary' aria-label='Add'
             className={classes.createButton}><Add/></Fab>
        <Drawer open={this.state.open} anchor='right' classes={{ paper: classes.drawerPaper }} onClose={this.handleClose.bind(this)}>
          <div className={classes.header}>
            <IconButton aria-label='Close' className={classes.closeButton} onClick={this.handleClose.bind(this)}>
              <Close fontSize='small'/>
            </IconButton>
            <Typography variant='h6'>
              {t('Create a marking definition')}
            </Typography>
            <Button variant='contained' size='small' color='secondary' className={classes.importButton}>
              {t('Import')}
            </Button>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{ definition_type: '', definition: '', color: '', level: '' }}
              validationSchema={markingDefinitionValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onReset.bind(this)}
              render={({ submitForm, handleReset, isSubmitting }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field name='definition_type' component={TextField} label={t('Type')} fullWidth={true}/>
                  <Field name='definition' component={TextField} label={t('Definition')} fullWidth={true} style={{ marginTop: 20 }}/>
                  <Field name='color' component={TextField} label={t('Color')} fullWidth={true} style={{ marginTop: 20 }}/>
                  <Field name='level' component={TextField} label={t('Level')} fullWidth={true} type='number' style={{ marginTop: 20 }}/>
                  <div className={classes.buttons}>
                    <Button variant="contained" onClick={handleReset} disabled={isSubmitting} classes={{ root: classes.button }}>
                      {t('Cancel')}
                    </Button>
                    <Button variant='contained' color='primary' onClick={submitForm} disabled={isSubmitting} classes={{ root: classes.button }}>
                      {t('Create')}
                    </Button>
                  </div>
                </Form>
              )}
            />
          </div>
        </Drawer>
      </div>
    );
  }
}

MarkingDefinitionCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(MarkingDefinitionCreation);
