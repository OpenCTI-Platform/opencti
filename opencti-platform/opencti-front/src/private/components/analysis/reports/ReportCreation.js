import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Form, Formik, Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import * as R from 'ramda';
import { dayStartDate, parse } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { attributesQuery } from '../../settings/attributes/AttributesLines';
import Loader from '../../../../components/Loader';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import CreatedByField from '../../common/form/CreatedByField';
import MarkDownField from '../../../../components/MarkDownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import ExternalReferencesField from '../../common/form/ExternalReferencesField';
import ItemIcon from '../../../../components/ItemIcon';
import AutocompleteField from '../../../../components/AutocompleteField';
import AutocompleteFreeSoloField from '../../../../components/AutocompleteFreeSoloField';
import Security, { SETTINGS_SETLABELS } from '../../../../utils/Security';
import DateTimePickerField from '../../../../components/DateTimePickerField';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
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
    backgroundColor: theme.palette.background.nav,
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
  icon: {
    paddingTop: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  autoCompleteIndicator: {
    display: 'none',
  },
});

const reportMutation = graphql`
  mutation ReportCreationMutation($input: ReportAddInput!) {
    reportAdd(input: $input) {
      ...ReportLine_node
    }
  }
`;

const reportValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  published: Yup.date()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .required(t('This field is required')),
  confidence: Yup.number().required(t('This field is required')),
  report_types: Yup.array().required(t('This field is required')),
  description: Yup.string().nullable(),
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

class ReportCreation extends Component {
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
    const finalValues = R.pipe(
      R.assoc('confidence', parseInt(values.confidence, 10)),
      R.assoc('published', parse(values.published).format()),
      R.assoc('report_types', R.pluck('value', values.report_types)),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc('objectLabel', R.pluck('value', values.objectLabel)),
      R.assoc('externalReferences', R.pluck('value', values.externalReferences)),
    )(values);
    commitMutation({
      mutation: reportMutation,
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        const payload = store.getRootField('reportAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node');
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
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <QueryRenderer
            query={attributesQuery}
            variables={{ key: 'report_types' }}
            render={({ props }) => {
              if (props && props.runtimeAttributes) {
                const reportEdges = props.runtimeAttributes.edges.map(
                  (e) => e.node.value,
                );
                const elements = R.uniq([
                  ...reportEdges,
                  'threat-report',
                  'internal-report',
                ]);
                return (
                  <div>
                    <div className={classes.header}>
                      <IconButton
                        aria-label="Close"
                        className={classes.closeButton}
                        onClick={this.handleClose.bind(this)}
                        size="large"
                        color="primary"
                      >
                        <Close fontSize="small" color="primary" />
                      </IconButton>
                      <Typography variant="h6">
                        {t('Create a report')}
                      </Typography>
                    </div>
                    <div className={classes.container}>
                      <Formik
                        initialValues={{
                          name: '',
                          published: dayStartDate(),
                          confidence: 75,
                          description: '',
                          report_types: [],
                          createdBy: '',
                          objectMarking: [],
                          objectLabel: [],
                          externalReferences: [],
                        }}
                        validationSchema={reportValidation(t)}
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
                              variant="standard"
                              name="name"
                              label={t('Name')}
                              fullWidth={true}
                            />
                            <Field
                              component={DateTimePickerField}
                              name="published"
                              TextFieldProps={{
                                label: t('Publication date'),
                                variant: 'standard',
                                fullWidth: true,
                                style: { marginTop: 20 },
                              }}
                            />
                            <Security
                              needs={[SETTINGS_SETLABELS]}
                              placeholder={
                                <Field
                                  component={AutocompleteField}
                                  style={{ marginTop: 20 }}
                                  name="report_types"
                                  multiple={true}
                                  createLabel={t('Add')}
                                  textfieldprops={{
                                    variant: 'standard',
                                    label: t('Report types'),
                                  }}
                                  options={elements.map((n) => ({
                                    id: n,
                                    value: n,
                                    label: n,
                                  }))}
                                  renderOption={(optionProps, option) => (
                                    <li {...optionProps}>
                                      <div className={classes.icon}>
                                        <ItemIcon type="attribute" />
                                      </div>
                                      <div className={classes.text}>
                                        {option.label}
                                      </div>
                                    </li>
                                  )}
                                  classes={{
                                    clearIndicator:
                                      classes.autoCompleteIndicator,
                                  }}
                                />
                              }
                            >
                              <Field
                                component={AutocompleteFreeSoloField}
                                style={{ marginTop: 20 }}
                                name="report_types"
                                multiple={true}
                                createLabel={t('Add')}
                                textfieldprops={{
                                  variant: 'standard',
                                  label: t('Report types'),
                                }}
                                options={elements.map((n) => ({
                                  id: n,
                                  value: n,
                                  label: n,
                                }))}
                                renderOption={(optionProps, option) => (
                                  <li {...optionProps}>
                                    <div className={classes.icon}>
                                      <ItemIcon type="attribute" />
                                    </div>
                                    <div className={classes.text}>
                                      {option.label}
                                    </div>
                                  </li>
                                )}
                                classes={{
                                  clearIndicator: classes.autoCompleteIndicator,
                                }}
                              />
                            </Security>
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
                            <ExternalReferencesField
                              name="externalReferences"
                              style={{ marginTop: 20, width: '100%' }}
                              setFieldValue={setFieldValue}
                              values={values.externalReferences}
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
                                color="secondary"
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
                  </div>
                );
              }
              return <Loader variant="inElement" />;
            }}
          />
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

export default R.compose(inject18n, withStyles(styles))(ReportCreation);
