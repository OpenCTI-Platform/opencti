import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql, loadQuery, usePreloadedQuery } from 'react-relay';
import * as R from 'ramda';
import MenuItem from '@mui/material/MenuItem';
import inject18n from '../../../../components/i18n';
import { commitMutation, environment, MESSAGING$ } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SwitchField from '../../../../components/SwitchField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { dayStartDate } from '../../../../utils/Time';
import SelectField from '../../../../components/SelectField';
import AutocompleteField from '../../../../components/AutocompleteField';
import ItemIcon from '../../../../components/ItemIcon';
import { insertNode } from '../../../../utils/store';

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
    padding: '20px 0px 20px 60px',
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
  title: {
    float: 'left',
  },
});

const syncCreationMutation = graphql`
  mutation SyncCreationMutation($input: SynchronizerAddInput!) {
    synchronizerAdd(input: $input) {
      ...SyncLine_node
    }
  }
`;

export const syncCheckMutation = graphql`
  mutation SyncCreationCheckMutation($input: SynchronizerAddInput!) {
    synchronizerTest(input: $input)
  }
`;

const syncCreationValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  uri: Yup.string().required(t('This field is required')),
  token: Yup.string(),
  stream_id: Yup.string().required(t('This field is required')),
  current_state: Yup.date()
    .nullable()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  listen_deletion: Yup.bool(),
  no_dependencies: Yup.bool(),
  ssl_verify: Yup.bool(),
});

export const syncStreamCollectionQuery = `
    query SyncCreationStreamCollectionQuery {
      streamCollections {
        edges {
          node {
            id
            name
          }
        }
      }
    }
  `;

const syncCreationUserQuery = graphql`
  query SyncCreationUserQuery {
    users {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const queryRef = loadQuery(environment, syncCreationUserQuery);
const SyncCreation = (props) => {
  const { t, classes } = props;
  const [open, setOpen] = useState(false);
  const [verified, setVerified] = useState(false);
  const [streams, setStreams] = useState([]);

  const { users } = usePreloadedQuery(syncCreationUserQuery, queryRef);

  const handleOpen = () => {
    setOpen(true);
  };
  const handleClose = () => {
    setOpen(false);
  };
  const handleVerify = (values) => {
    commitMutation({
      mutation: syncCheckMutation,
      variables: {
        input: values,
      },
      onCompleted: (data) => {
        if (data && data.synchronizerTest === 'Connection success') {
          MESSAGING$.notifySuccess(t('Connection successfully verified'));
          setVerified(true);
        }
      },
      onError: (e, messages) => {
        MESSAGING$.messages.next(messages);
        setVerified(false);
      },
    });
  };

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    commitMutation({
      mutation: syncCreationMutation,
      variables: {
        input: values,
      },
      updater: (store) => {
        insertNode(store, 'Pagination_synchronizers', props.paginationOptions, 'synchronizerAdd');
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
      },
    });
  };

  const onReset = () => {
    handleClose();
  };

  const handleGetStreams = async (uri) => {
    const res = await fetch(`${uri}/graphql`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: syncStreamCollectionQuery }),
    });
    if (!res.ok) {
      MESSAGING$.notifyError('Error getting the streams from distant OpenCTI');
      return;
    }
    const result = await res.json();
    setStreams([
      { value: 'live', label: 'live' },
      ...result.data.streamCollections.edges.map(({ node }) => ({ value: node.id, label: node.name })),
    ]);
  };

  return (
    <div>
      <Fab
        onClick={handleOpen}
        color="secondary"
        aria-label="Add"
        className={classes.createButton}
      >
        <Add />
      </Fab>
      <Drawer
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}
      >
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t('Create a synchronizer')}</Typography>
        </div>
        <div className={classes.container}>
          <Formik
            initialValues={{
              name: '',
              uri: '',
              token: '',
              current_state: dayStartDate(),
              stream_id: 'live',
              no_dependencies: false,
              listen_deletion: true,
              ssl_verify: false,
            }}
            validationSchema={syncCreationValidation(t)}
            onSubmit={onSubmit}
            onReset={onReset}
          >
            {({ submitForm, handleReset, isSubmitting, values, setFieldValue }) => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name="name"
                  label={t('Name')}
                  fullWidth={true}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="uri"
                  label={t('Remote OpenCTI URL')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="token"
                  label={t('Remote OpenCTI token')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={SelectField}
                  variant="standard"
                  name="stream_id"
                  label={t('Remote OpenCTI stream ID')}
                  containerstyle={{ width: '100%' }}
                  style={{ marginTop: 20 }}
                  onOpen={() => (values.uri ? handleGetStreams(values.uri) : {})}
                >
                  {streams.map(({ value, label }) => (
                    <MenuItem key={value} value={value}>{label}</MenuItem>
                  ))}
                </Field>
                <Field
                  component={AutocompleteField}
                  name="user_id"
                  onChange={(name, value) => setFieldValue(name, value.value)}
                  textfieldprops={{
                    variant: 'standard',
                    label: t('User applied for this synchronizer'),
                  }}
                  containerstyle={{ width: '100%' }}
                  style={{ marginTop: 20 }}
                  noOptionsText={t('No available options')}
                  options={users.edges.map(({ node }) => ({
                    id: node.id,
                    value: node.id,
                    label: node.name,
                  }))}
                  renderOption={(optionProps, option) => (
                    <li {...optionProps}>
                      <div className={classes.icon}>
                        <ItemIcon type="User" />
                      </div>
                      <div className={classes.text}>
                        {option.label}
                      </div>
                    </li>
                  )}
                />
                <Field
                  component={DateTimePickerField}
                  name="current_state"
                  TextFieldProps={{
                    label: t('Starting synchronization (empty = from start)'),
                    variant: 'standard',
                    fullWidth: true,
                    style: { marginTop: 20 },
                  }}
                />
                <Field
                  component={SwitchField}
                  type="checkbox"
                  name="listen_deletion"
                  containerstyle={{ marginTop: 20 }}
                  label={t('Take deletions into account')}
                />
                <Field
                  component={SwitchField}
                  type="checkbox"
                  name="no_dependencies"
                  label={t('Avoid dependencies resolution')}
                />
                <Field
                  component={SwitchField}
                  type="checkbox"
                  name="ssl_verify"
                  label={t('Verify SSL certificate')}
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
                    onClick={() => handleVerify(values)}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t('Verify')}
                  </Button>
                  <Button
                    variant="contained"
                    color="secondary"
                    onClick={submitForm}
                    disabled={!verified || isSubmitting}
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
};

SyncCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(SyncCreation);
