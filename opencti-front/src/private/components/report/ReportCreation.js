import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { fetchQuery, commitMutation } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import Fab from '@material-ui/core/Fab';
import { Add, Close } from '@material-ui/icons';
import {
  compose, head, pathOr, pipe, map, pluck,
} from 'ramda';
import * as Yup from 'yup';
import graphql from 'babel-plugin-relay/macro';
import { ConnectionHandler } from 'relay-runtime';
import { parse } from '../../../utils/Time';
import inject18n from '../../../components/i18n';
import environment from '../../../relay/environment';
import Autocomplete from '../../../components/Autocomplete';
import AutocompleteCreate from '../../../components/AutocompleteCreate';
import TextField from '../../../components/TextField';
import { markingDefinitionsLinesSearchQuery } from '../marking_definition/MarkingDefinitionsLines';
import IdentityCreation from '../identity/IdentityCreation';

const styles = theme => ({
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

const reportMutation = graphql`
    mutation ReportCreationMutation($input: ReportAddInput!) {
        reportAdd(input: $input) {
            ...ReportLine_report
        }
    }
`;

const reportValidation = t => Yup.object().shape({
  name: Yup.string()
    .required(t('This field is required')),
  published: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_reports',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

export const reportCreationIdentitiesSearchQuery = graphql`
    query ReportCreationIdentitiesSearchQuery($search: String) {
        identities(search: $search) {
            edges {
                node {
                    id
                    name
                }
            }
        }
    }
`;

class ReportCreation extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false, identities: [], identityCreation: false, identityInput: '', markingDefinitions: [],
    };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  searchIdentities(event) {
    fetchQuery(environment, reportCreationIdentitiesSearchQuery, { search: event.target.value }).then((data) => {
      const identities = pipe(
        pathOr([], ['identities', 'edges']),
        map(n => ({ label: n.node.name, value: n.node.id })),
      )(data);
      this.setState({ identities });
    });
  }

  handleOpenIdentityCreation(inputValue) {
    this.setState({ identityCreation: true, identityInput: inputValue });
  }

  handleCloseIdentityCreation() {
    this.setState({ identityCreation: false });
  }

  searchMarkingDefinitions(event) {
    fetchQuery(environment, markingDefinitionsLinesSearchQuery, { search: event.target.value }).then((data) => {
      const markingDefinitions = pipe(
        pathOr([], ['markingDefinitions', 'edges']),
        map(n => ({ label: n.node.definition, value: n.node.id })),
      )(data);
      this.setState({ markingDefinitions });
    });
  }

  onSubmit(values, { setSubmitting, resetForm, setErrors }) {
    values.published = parse(values.published).format();
    values.createdByRef = values.createdByRef.value;
    values.markingDefinitions = pluck('value', values.markingDefinitions);
    commitMutation(environment, {
      mutation: reportMutation,
      variables: {
        input: values,
      },
      updater: (store) => {
        const payload = store.getRootField('reportAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node'); // Creation of the pagination container.
        const container = store.getRoot();
        sharedUpdater(store, container.getDataID(), this.props.paginationOptions, newEdge);
      },
      /* optimisticUpdater: (store) => {
        const root = store.getRoot();
        const user = root.getLinkedRecord('me');
        const id = Math.floor(Math.random() * 999999) + 100000;
        const node = store.create(`client:newReport:V${id}`, 'Report');
        node.setValue(`client:newReport:V${id}`, 'id');
        node.setValue('YOOOOOOOOOOOOOOOOOOOO', 'name');
        node.setValue(values.description, 'description');
        const newEdge = store.create(`client:newEdge:V${id}`, 'reportEdge');
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
              {t('Create a report')}
            </Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                name: '', published: '', description: '', createdByRef: '', markingDefinitions: [],
              }}
              validationSchema={reportValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onReset.bind(this)}
              render={({
                submitForm, handleReset, isSubmitting, setFieldValue,
              }) => (
                <div>
                  <Form style={{ margin: '20px 0 20px 0' }}>
                    <Field name='name' component={TextField} label={t('Name')} fullWidth={true}/>
                    <Field name='published' component={TextField} label={t('Publication date')} fullWidth={true} style={{ marginTop: 20 }}/>
                    <Field name='description' component={TextField} label={t('Description')}
                           fullWidth={true} multiline={true} rows='4' style={{ marginTop: 20 }}/>
                    <Field
                      name='createdByRef'
                      component={AutocompleteCreate}
                      multiple={false}
                      handleCreate={this.handleOpenIdentityCreation.bind(this)}
                      label={t('Author')}
                      options={this.state.identities}
                      onInputChange={this.searchIdentities.bind(this)}
                    />
                    <Field
                      name='markingDefinitions'
                      component={Autocomplete}
                      multiple={true}
                      label={t('Marking')}
                      options={this.state.markingDefinitions}
                      onInputChange={this.searchMarkingDefinitions.bind(this)}
                    />
                    <div className={classes.buttons}>
                      <Button variant="contained" onClick={handleReset} disabled={isSubmitting} classes={{ root: classes.button }}>
                        {t('Cancel')}
                      </Button>
                      <Button variant='contained' color='primary' onClick={submitForm} disabled={isSubmitting} classes={{ root: classes.button }}>
                        {t('Create')}
                      </Button>
                    </div>
                  </Form>
                  <IdentityCreation
                    contextual={true}
                    inputValue={this.state.identityInput}
                    open={this.state.identityCreation}
                    handleClose={this.handleCloseIdentityCreation.bind(this)}
                    creationCallback={(data) => {
                      setFieldValue('createdByRef', { label: data.identityAdd.name, value: data.identityAdd.id });
                    }}
                  />
                </div>
              )}
            />
          </div>
        </Drawer>
      </div>
    );
  }
}

ReportCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(ReportCreation);
