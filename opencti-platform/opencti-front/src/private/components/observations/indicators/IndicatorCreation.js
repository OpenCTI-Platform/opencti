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
import MenuItem from '@material-ui/core/MenuItem';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import DatePickerField from '../../../../components/DatePickerField';
import SelectField from '../../../../components/SelectField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import TypesField from '../TypesField';
import SwitchField from '../../../../components/SwitchField';
import MarkDownField from '../../../../components/MarkDownField';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';

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

const indicatorMutation = graphql`
  mutation IndicatorCreationMutation($input: IndicatorAddInput!) {
    indicatorAdd(input: $input) {
      ...IndicatorLine_node
    }
  }
`;

const indicatorValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string(),
  pattern: Yup.string().required(t('This field is required')),
  pattern_type: Yup.string().required(t('This field is required')),
  x_opencti_main_observable_type: Yup.string().required(
    t('This field is required'),
  ),
  x_opencti_detection: Yup.boolean(),
  x_mitre_platforms: Yup.array(),
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_indicators',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class IndicatorCreation extends Component {
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
        killChainPhases: pluck('value'),
        createdBy: path(['value']),
        objectMarking: pluck('value'),
        objectLabel: pluck('value'),
      },
      values,
    );
    commitMutation({
      mutation: indicatorMutation,
      variables: {
        input: adaptedValues,
      },
      updater: (store) => {
        const payload = store.getRootField('indicatorAdd');
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

  render() {
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
            <Typography variant="h6">{t('Create an indicator')}</Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                name: '',
                pattern: '',
                pattern_type: '',
                x_opencti_main_observable_type: '',
                x_mitre_platforms: [],
                valid_from: null,
                valid_until: null,
                description: '',
                createdBy: '',
                objectMarking: [],
                killChainPhases: [],
                objectLabel: [],
                x_opencti_detection: false,
              }}
              validationSchema={indicatorValidation(t)}
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
                  <Field
                    component={TextField}
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                  />
                  <Field
                    component={SelectField}
                    name="pattern_type"
                    label={t('Pattern type')}
                    fullWidth={true}
                    containerstyle={{ marginTop: 20, width: '100%' }}
                  >
                    <MenuItem value="stix">STIX</MenuItem>
                    <MenuItem value="pcre">PCRE</MenuItem>
                    <MenuItem value="sigma">SIGMA</MenuItem>
                    <MenuItem value="snort">SNORT</MenuItem>
                    <MenuItem value="suricata">Suricata</MenuItem>
                    <MenuItem value="yara">YARA</MenuItem>
                    <MenuItem value="tanium-signal">Tanium Signal</MenuItem>
                  </Field>
                  <Field
                    component={TextField}
                    name="pattern"
                    label={t('Pattern')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                    style={{ marginTop: 20 }}
                    detectDuplicate={['Indicator']}
                  />
                  <TypesField
                    name="x_opencti_main_observable_type"
                    label={t('Main observable type')}
                    containerstyle={{ marginTop: 20, width: '100%' }}
                  />
                  <Field
                    component={DatePickerField}
                    name="valid_from"
                    label={t('Valid from')}
                    invalidDateMessage={t(
                      'The value must be a date (YYYY-MM-DD)',
                    )}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={DatePickerField}
                    name="valid_until"
                    label={t('Valid until')}
                    invalidDateMessage={t(
                      'The value must be a date (YYYY-MM-DD)',
                    )}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={SelectField}
                    name="x_mitre_platforms"
                    multiple={true}
                    label={t('Platforms')}
                    fullWidth={true}
                    containerstyle={{ marginTop: 20, width: '100%' }}
                  >
                    <MenuItem value="Android">{t('Android')}</MenuItem>
                    <MenuItem value="macOS">{t('macOS')}</MenuItem>
                    <MenuItem value="Linux">{t('Linux')}</MenuItem>
                    <MenuItem value="Windows">{t('Windows')}</MenuItem>
                  </Field>
                  <Field
                    component={MarkDownField}
                    name="description"
                    label={t('Description')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                    style={{ marginTop: 20 }}
                  />
                  <KillChainPhasesField
                    name="killChainPhases"
                    style={{ marginTop: 20, width: '100%' }}
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
                  <Field
                    component={SwitchField}
                    type="checkbox"
                    name="x_opencti_detection"
                    label={t('Detection')}
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
}

IndicatorCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  openExports: PropTypes.bool,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(IndicatorCreation);
