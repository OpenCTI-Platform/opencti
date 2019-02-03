import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Field, Form } from 'formik';
import { ConnectionHandler } from 'relay-runtime';
import { compose } from 'ramda';
import * as Yup from 'yup';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogActions from '@material-ui/core/DialogActions';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import MenuItem from '@material-ui/core/MenuItem';
import Fab from '@material-ui/core/Fab';
import { Add, Close } from '@material-ui/icons';
import { commitMutation } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import TextField from '../../../components/TextField';
import Select from '../../../components/Select';

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
  dialogActions: {
    padding: '0 17px 20px 0',
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

const stixDomainEntityCreationMutation = graphql`
    mutation StixDomainEntityCreationMutation($input: StixDomainEntityAddInput!) {
        stixDomainEntityAdd(input: $input) {
            id
            type
            name
            description
        }
    }
`;

const stixDomainEntityValidation = t => Yup.object().shape({
  name: Yup.string()
    .required(t('This field is required')),
  description: Yup.string(),
  type: Yup.string()
    .required(t('This field is required')),
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_stixDomainEntities',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class StixDomainEntityCreation extends Component {
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
    commitMutation({
      mutation: stixDomainEntityCreationMutation,
      variables: {
        input: values,
      },
      updater: (store) => {
        const payload = store.getRootField('stixDomainEntityAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node'); // Creation of the pagination container.
        const container = store.getRoot();
        sharedUpdater(store, container.getDataID(), this.props.paginationOptions, newEdge);
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
      },
    });
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
        <Fab onClick={this.handleOpen.bind(this)}
             color='secondary' aria-label='Add'
             className={classes.createButton}><Add/></Fab>
        <Drawer open={this.state.open} anchor='right' classes={{ paper: classes.drawerPaper }} onClose={this.handleClose.bind(this)}>
          <div className={classes.header}>
            <IconButton aria-label='Close' className={classes.closeButton} onClick={this.handleClose.bind(this)}>
              <Close fontSize='small'/>
            </IconButton>
            <Typography variant='h6'>
              {t('Create an entity')}
            </Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                name: '', description: '', type: '',
              }}
              validationSchema={stixDomainEntityValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onResetClassic.bind(this)}
              render={({ submitForm, handleReset, isSubmitting }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field name='name' component={TextField} label={t('Name')} fullWidth={true}/>
                  <Field name='description' component={TextField} label={t('Description')}
                         fullWidth={true} multiline={true} rows='4' style={{ marginTop: 20 }}/>
                  <Field name='type'
                         component={Select}
                         label={t('Entity type')}
                         fullWidth={true}
                         displayEmpty={true}
                         inputProps={{
                           name: 'type',
                           id: 'type',
                         }}
                         containerstyle={{ marginTop: 20, width: '100%' }}
                  >
                    <MenuItem value='Organization'>{t('Organization')}</MenuItem>
                    <MenuItem value='Threat-Actor'>{t('Threat actor')}</MenuItem>
                    <MenuItem value='Intrusion-Set'>{t('Intrusion set')}</MenuItem>
                    <MenuItem value='Campaign'>{t('Campaign')}</MenuItem>
                    <MenuItem value='Incident'>{t('Incident')}</MenuItem>
                    <MenuItem value='Malware'>{t('Malware')}</MenuItem>
                    <MenuItem value='Tool'>{t('Tool')}</MenuItem>
                    <MenuItem value='Vulnerability'>{t('Vulnerability')}</MenuItem>
                    <MenuItem value='City'>{t('City')}</MenuItem>
                    <MenuItem value='Country'>{t('Country')}</MenuItem>
                  </Field>
                  <div className={classes.buttons}>
                    <Button variant='contained' onClick={handleReset} disabled={isSubmitting} classes={{ root: classes.button }}>
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

  renderContextual() {
    const {
      t, classes, inputValue, display,
    } = this.props;
    return (
      <div style={{ display: display ? 'block' : 'none' }}>
        <Fab onClick={this.handleOpen.bind(this)}
             color='secondary' aria-label='Add'
             className={classes.createButton}><Add/></Fab>
        <Formik
          enableReinitialize={true}
          initialValues={{
            name: inputValue, description: '', type: '',
          }}
          validationSchema={stixDomainEntityValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
          onReset={this.onResetContextual.bind(this)}
          render={({ submitForm, handleReset, isSubmitting }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Dialog open={this.state.open} onClose={this.handleClose.bind(this)}>
                <DialogTitle>
                  {t('Create an entity')}
                </DialogTitle>
                <DialogContent>
                  <Field name='name' component={TextField} label={t('Name')} fullWidth={true}/>
                  <Field name='description' component={TextField} label={t('Description')}
                         fullWidth={true} multiline={true} rows='4' style={{ marginTop: 20 }}/>
                  <Field name='type'
                         component={Select}
                         label={t('Entity type')}
                         fullWidth={true}
                         displayEmpty={true}
                         inputProps={{
                           name: 'type',
                           id: 'type',
                         }}
                         containerstyle={{ marginTop: 20, width: '100%' }}
                  >
                    <MenuItem value='Organization'>{t('Organization')}</MenuItem>
                    <MenuItem value='Threat-Actor'>{t('Threat actor')}</MenuItem>
                    <MenuItem value='Intrusion-Set'>{t('Intrusion set')}</MenuItem>
                    <MenuItem value='Campaign'>{t('Campaign')}</MenuItem>
                    <MenuItem value='Incident'>{t('Incident')}</MenuItem>
                    <MenuItem value='Malware'>{t('Malware')}</MenuItem>
                    <MenuItem value='Tool'>{t('Tool')}</MenuItem>
                    <MenuItem value='Vulnerability'>{t('Vulnerability')}</MenuItem>
                    <MenuItem value='City'>{t('City')}</MenuItem>
                    <MenuItem value='Country'>{t('Country')}</MenuItem>
                  </Field>
                </DialogContent>
                <DialogActions classes={{ root: classes.dialogActions }}>
                  <Button variant='contained' onClick={handleReset} disabled={isSubmitting} classes={{ root: classes.button }}>
                    {t('Cancel')}
                  </Button>
                  <Button variant='contained' color='primary' onClick={submitForm} disabled={isSubmitting} classes={{ root: classes.button }}>
                    {t('Create')}
                  </Button>
                </DialogActions>
              </Dialog>
            </Form>
          )}
        />
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

StixDomainEntityCreation.propTypes = {
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
)(StixDomainEntityCreation);
