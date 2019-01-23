import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Field, Form } from 'formik';
import { ConnectionHandler } from 'relay-runtime';
import { compose } from 'ramda';
import * as Yup from 'yup';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import { commitMutation } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import TextField from '../../../components/TextField';

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
    zIndex: 2000,
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

const stixRelationCreationQuery = graphql`
    query StixRelationCreationQuery($fromId: String!, $toId: String!) {
        stixRelations(fromId: $fromId, toId: $toId) {
            edges {
                node {
                    id
                    relationship_type
                    weight
                    description
                    first_seen
                    last_seen
                }
            }
        }
    }
`;

const stixRelationCreationMutation = graphql`
    mutation StixRelationCreationMutation($input: StixRelationAddInput!) {
        stixRelationAdd(input: $input) {
            id
            relationship_type
            weight
            first_seen
            last_seen
        }
    }
`;

const stixRelationValidation = t => Yup.object().shape({
  type: Yup.number()
    .required(t('This field is required')),
  weight: Yup.number()
    .required(t('This field is required')),
  first_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)')),
  last_seen: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)')),
  description: Yup.string(),
});

class StixRelationCreation extends Component {
  onSubmit(values, { setSubmitting, resetForm }) {
    commitMutation({
      mutation: stixRelationCreationMutation,
      variables: {
        input: values,
      },
      setSubmitting,
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        this.props.handleResult(response);
      },
    });
  }

  renderForm() {
    const { t, classes, handleClose } = this.props;
    return (
      <Formik
        enableReinitialize={true}
        initialValues={{
          type: '', weight: '', first_seen: '', last_seen: '', description: '',
        }}
        validationSchema={stixRelationValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
        onReset={handleClose.bind(this)}
        render={({ submitForm, handleReset, isSubmitting }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <DialogTitle>
              {t('Create a relationship')}
            </DialogTitle>
            <DialogContent>
              <Field name='source_name' component={TextField} label={t('Source name')} fullWidth={true}/>
              <Field name='external_id' component={TextField} label={t('External ID')} fullWidth={true} style={{ marginTop: 20 }}/>
              <Field name='url' component={TextField} label={t('URL')} fullWidth={true} style={{ marginTop: 20 }}/>
              <Field name='description' component={TextField} label={t('Description')}
                     fullWidth={true} multiline={true} rows='4' style={{ marginTop: 20 }}/>
            </DialogContent>
            <DialogActions>
              <Button variant="contained" onClick={handleReset} disabled={isSubmitting} classes={{ root: classes.button }}>
                {t('Cancel')}
              </Button>
              <Button variant='contained' color='primary' onClick={submitForm} disabled={isSubmitting} classes={{ root: classes.button }}>
                {t('Create')}
              </Button>
            </DialogActions>
          </Form>
        )}
      />
    );
  }

  render() {
    const { t, open, handleClose } = this.props;
    return (
      <Dialog open={open} onClose={handleClose.bind(this)}>
        {this.renderForm()}
      </Dialog>
    );
  }
}

StixRelationCreation.propTypes = {
  open: PropTypes.bool,
  fromId: PropTypes.string,
  toId: PropTypes.string,
  handleResult: PropTypes.func,
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixRelationCreation);
