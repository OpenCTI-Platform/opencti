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
  compose, pipe, pluck, assoc,
} from 'ramda';
import * as Yup from 'yup';
import graphql from 'babel-plugin-relay/macro';
import MenuItem from '@material-ui/core/MenuItem';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import SelectField from '../../../../components/SelectField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { insertNode } from '../../../../utils/Store';

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
    right: 30,
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

const threatActorMutation = graphql`
  mutation ThreatActorCreationMutation($input: ThreatActorAddInput!) {
    threatActorAdd(input: $input) {
      ...ThreatActorCard_node
    }
  }
`;

const threatActorValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  threat_actor_types: Yup.array(),
  confidence: Yup.number(),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class ThreatActorCreation extends Component {
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
    const finalValues = pipe(
      assoc('createdBy', values.createdBy.value),
      assoc('objectMarking', pluck('value', values.objectMarking)),
      assoc('objectLabel', pluck('value', values.objectLabel)),
    )(values);
    commitMutation({
      mutation: threatActorMutation,
      variables: {
        input: finalValues,
      },
      updater: (store) => insertNode(
        store,
        'Pagination_threatActors',
        this.props.paginationOptions,
        'threatActorAdd',
      ),
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
            <Typography variant="h6">{t('Create a threat actor')}</Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                name: '',
                threat_actor_types: [],
                confidence: 15,
                description: '',
                createdBy: '',
                objectMarking: [],
                objectLabel: [],
              }}
              validationSchema={threatActorValidation(t)}
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
                    detectDuplicate={[
                      'Threat-Actor',
                      'Intrusion-Set',
                      'Campaign',
                      'Malware',
                    ]}
                  />
                  <Field
                    component={SelectField}
                    name="threat_actor_types"
                    label={t('Threat actor types')}
                    fullWidth={true}
                    multiple={true}
                    containerstyle={{ width: '100%', marginTop: 20 }}
                  >
                    <MenuItem key="activist" value="activist">
                      {t('activist')}
                    </MenuItem>
                    <MenuItem key="competitor" value="competitor">
                      {t('competitor')}
                    </MenuItem>
                    <MenuItem key="crime-syndicate" value="crime-syndicate">
                      {t('crime-syndicate')}
                    </MenuItem>
                    <MenuItem key="criminal'" value="criminal'">
                      {t('criminal')}
                    </MenuItem>
                    <MenuItem key="hacker" value="hacker">
                      {t('hacker')}
                    </MenuItem>
                    <MenuItem
                      key="insider-accidental"
                      value="insider-accidental"
                    >
                      {t('insider-accidental')}
                    </MenuItem>
                    <MenuItem
                      key="insider-disgruntled"
                      value="insider-disgruntled"
                    >
                      {t('insider-disgruntled')}
                    </MenuItem>
                    <MenuItem key="nation-state" value="nation-state">
                      {t('nation-state')}
                    </MenuItem>
                    <MenuItem key="sensationalist" value="sensationalist">
                      {t('sensationalist')}
                    </MenuItem>
                    <MenuItem key="spy" value="spy">
                      {t('spy')}
                    </MenuItem>
                    <MenuItem key="terrorist" value="terrorist">
                      {t('terrorist')}
                    </MenuItem>
                    <MenuItem key="unknown" value="unknown">
                      {t('unknown')}
                    </MenuItem>
                  </Field>
                  <ConfidenceField
                    name="confidence"
                    label={t('Confidence')}
                    fullWidth={true}
                    containerstyle={{ width: '100%', marginTop: 20 }}
                  />
                  <Field
                    component={MarkDownField}
                    name="description"
                    label={t('Description')}
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
          </div>
        </Drawer>
      </div>
    );
  }
}

ThreatActorCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(ThreatActorCreation);
