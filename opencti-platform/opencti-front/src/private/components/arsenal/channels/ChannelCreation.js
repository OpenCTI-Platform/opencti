import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { Formik, Form, Field } from 'formik';
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
import inject18n from '../../../../components/i18n';
import {
  QueryRenderer,
  commitMutation,
  handleErrorInForm,
} from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import ExternalReferencesField from '../../common/form/ExternalReferencesField';
import { attributesQuery } from '../../settings/attributes/AttributesLines';
import Loader from '../../../../components/Loader';
import Security, { SETTINGS_SETLABELS } from '../../../../utils/Security';
import AutocompleteField from '../../../../components/AutocompleteField';
import ItemIcon from '../../../../components/ItemIcon';
import AutocompleteFreeSoloField from '../../../../components/AutocompleteFreeSoloField';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
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

const channelMutation = graphql`
  mutation ChannelCreationMutation($input: ChannelAddInput!) {
    channelAdd(input: $input) {
      ...ChannelLine_node
    }
  }
`;

const channelValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  channel_types: Yup.array().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_channels',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class ChannelCreation extends Component {
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

  onSubmit(values, { setSubmitting, setErrors, resetForm }) {
    const finalValues = R.pipe(
      R.assoc('channel_types', R.pluck('value', values.channel_types)),
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc('objectLabel', R.pluck('value', values.objectLabel)),
      R.assoc('externalReferences', R.pluck('value', values.externalReferences)),
    )(values);
    commitMutation({
      mutation: channelMutation,
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        const payload = store.getRootField('channelAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node'); // Creation of the pagination container.
        const container = store.getRoot();
        sharedUpdater(
          store,
          container.getDataID(),
          this.props.paginationOptions,
          newEdge,
        );
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
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
            variables={{ key: 'channel_types' }}
            render={({ props }) => {
              if (props && props.runtimeAttributes) {
                const channelEdges = props.runtimeAttributes.edges.map(
                  (e) => e.node.value,
                );
                const elements = R.uniq([
                  ...channelEdges,
                  'Twitter',
                  'Facebook',
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
                        {t('Create a channel')}
                      </Typography>
                    </div>
                    <div className={classes.container}>
                      <Formik
                        initialValues={{
                          name: '',
                          channel_types: [],
                          description: '',
                          createdBy: '',
                          objectMarking: [],
                          objectLabel: [],
                          externalReferences: [],
                        }}
                        validationSchema={channelValidation(t)}
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
                              detectDuplicate={['Channel', 'Malware']}
                            />
                            <Security
                              needs={[SETTINGS_SETLABELS]}
                              placeholder={
                                <Field
                                  component={AutocompleteField}
                                  style={{ marginTop: 20 }}
                                  name="channel_types"
                                  multiple={true}
                                  createLabel={t('Add')}
                                  textfieldprops={{
                                    variant: 'standard',
                                    label: t('Channel types'),
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
                                name="channel_types"
                                multiple={true}
                                createLabel={t('Add')}
                                textfieldprops={{
                                  variant: 'standard',
                                  label: t('Channel types'),
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
                              style={{
                                marginTop: 20,
                                width: '100%',
                              }}
                              setFieldValue={setFieldValue}
                            />
                            <ObjectLabelField
                              name="objectLabel"
                              style={{
                                marginTop: 20,
                                width: '100%',
                              }}
                              setFieldValue={setFieldValue}
                              values={values.objectLabel}
                            />
                            <ObjectMarkingField
                              name="objectMarking"
                              style={{
                                marginTop: 20,
                                width: '100%',
                              }}
                            />
                            <ExternalReferencesField
                              name="externalReferences"
                              style={{
                                marginTop: 20,
                                width: '100%',
                              }}
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

ChannelCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(ChannelCreation);
