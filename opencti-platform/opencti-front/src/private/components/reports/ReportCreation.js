import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Form, Formik, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import MenuItem from '@material-ui/core/MenuItem';
import Fab from '@material-ui/core/Fab';
import { Add, Close } from '@material-ui/icons';
import {
  compose, evolve, path, pluck,
} from 'ramda';
import * as Yup from 'yup';
import graphql from 'babel-plugin-relay/macro';
import { ConnectionHandler } from 'relay-runtime';
import { dayStartDate, parse } from '../../../utils/Time';
import inject18n from '../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../relay/environment';
import TextField from '../../../components/TextField';
import DatePickerField from '../../../components/DatePickerField';
import SelectField from '../../../components/SelectField';
import MarkingDefinitionsField from '../common/form/MarkingDefinitionsField';
import { attributesQuery } from '../settings/attributes/AttributesLines';
import Loader from '../../../components/Loader';
import TagsField from '../common/form/TagsField';
import CreatedByRefField from '../common/form/CreatedByRefField';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
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
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  report_class: Yup.string().required(t('This field is required')),
  description: Yup.string(),
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
    const adaptedValues = evolve(
      {
        published: parse(values.published).format(),
        createdByRef: path(['value']),
        markingDefinitions: pluck('value'),
        tags: pluck('value'),
      },
      values,
    );
    commitMutation({
      mutation: reportMutation,
      variables: {
        input: adaptedValues,
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
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <QueryRenderer
            query={attributesQuery}
            variables={{ type: 'report_class' }}
            render={({ props }) => {
              if (props && props.attributes) {
                const reportClassesEdges = props.attributes.edges;
                return (
                  <div>
                    <div className={classes.header}>
                      <IconButton
                        aria-label="Close"
                        className={classes.closeButton}
                        onClick={this.handleClose.bind(this)}
                      >
                        <Close fontSize="small" />
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
                          description: '',
                          report_class: '',
                          createdByRef: '',
                          markingDefinitions: [],
                          tags: [],
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
                              name="name"
                              label={t('Name')}
                              fullWidth={true}
                            />
                            <Field
                              component={DatePickerField}
                              name="published"
                              label={t('Publication date')}
                              invalidDateMessage={t(
                                'The value must be a date (YYYY-MM-DD)',
                              )}
                              fullWidth={true}
                              style={{ marginTop: 20 }}
                            />
                            <Field
                              component={SelectField}
                              name="report_class"
                              label={t('Report type')}
                              fullWidth={true}
                              containerstyle={{
                                marginTop: 20,
                                width: '100%',
                              }}
                            >
                              {reportClassesEdges.map((reportClassEdge) => (
                                <MenuItem
                                  key={reportClassEdge.node.id}
                                  value={reportClassEdge.node.value}
                                >
                                  {reportClassEdge.node.value}
                                </MenuItem>
                              ))}
                            </Field>
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

export default compose(inject18n, withStyles(styles))(ReportCreation);
