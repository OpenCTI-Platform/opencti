import React, { useEffect, useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import {
  CheckCircleOutlined,
  Close,
  WarningOutlined,
} from '@mui/icons-material';
import * as Yup from 'yup';
import * as R from 'ramda';
import Button from '@mui/material/Button';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import {
  commitMutation,
  fetchQuery,
  MESSAGING$,
} from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SwitchField from '../../../../components/SwitchField';
import { syncCheckMutation, syncStreamCollectionQuery } from './SyncCreation';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { buildDate } from '../../../../utils/Time';
import CreatorField from '../../common/form/CreatorField';
import { isNotEmptyField } from '../../../../utils/utils';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

const useStyles = makeStyles((theme) => ({
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
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  alert: {
    width: '100%',
    marginTop: 20,
  },
  message: {
    width: '100%',
    overflow: 'hidden',
  },
}));

const syncMutationFieldPatch = graphql`
  mutation SyncEditionFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    synchronizerEdit(id: $id) {
      fieldPatch(input: $input) {
        ...SyncEdition_synchronizer
      }
    }
  }
`;

const syncValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  uri: Yup.string().required(t('This field is required')),
  token: Yup.string(),
  stream_id: Yup.string().required(t('This field is required')),
  current_state_date: Yup.date()
    .nullable()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  listen_deletion: Yup.bool(),
  no_dependencies: Yup.bool(),
  ssl_verify: Yup.bool(),
  user_id: Yup.object().nullable(),
});

const SyncEditionContainer = ({ handleClose, synchronizer }) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const [streams, setStreams] = useState([]);
  const relatedUser = synchronizer.user
    ? { label: synchronizer.user.name, value: synchronizer.user.id }
    : '';
  const initialValues = R.pipe(
    R.assoc('current_state_date', buildDate(synchronizer.current_state_date)),
    R.assoc('user_id', relatedUser),
    R.pick([
      'name',
      'uri',
      'token',
      'stream_id',
      'user_id',
      'listen_deletion',
      'no_dependencies',
      'current_state_date',
      'ssl_verify',
    ]),
  )(synchronizer);
  const isStreamAccessible = isNotEmptyField(
    streams.find((s) => s.id === initialValues.stream_id),
  );
  const handleVerify = (values) => {
    commitMutation({
      mutation: syncCheckMutation,
      variables: {
        input: {
          ...values,
          user_id: values.user_id.value,
        },
      },
      onCompleted: (data) => {
        if (data && data.synchronizerTest === 'Connection success') {
          MESSAGING$.notifySuccess(t('Connection successfully verified'));
        }
      },
    });
  };
  const handleSubmitField = (name, value) => {
    const parsedValue = name === 'user_id' ? value.value : value;
    syncValidation(t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: syncMutationFieldPatch,
          variables: {
            id: synchronizer.id,
            input: { key: name, value: parsedValue || '' },
          },
        });
      })
      .catch(() => false);
  };

  const handleGetStreams = ({ uri, token, ssl_verify }) => {
    const args = { uri, token, ssl_verify: ssl_verify ?? false };
    fetchQuery(syncStreamCollectionQuery, args)
      .toPromise()
      .then((result) => {
        const resultStreams = [
          ...result.synchronizerFetch.map((s) => ({
            value: s.id,
            label: s.name,
            ...s,
          })),
        ];
        setStreams(resultStreams);
      })
      .catch(() => {
        setStreams([]);
      });
  };

  useEffect(() => {
    if (initialValues) {
      handleGetStreams(initialValues);
    }
  }, []);

  return (
    <div>
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
        <Typography variant="h6">{t('Update a synchronizer')}</Typography>
      </div>
      <div className={classes.container}>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={syncValidation(t)}
        >
          {({ values }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t('Name')}
                fullWidth={true}
                onSubmit={handleSubmitField}
              />
              <Alert
                icon={false}
                classes={{ root: classes.alert, message: classes.message }}
                severity="warning"
                variant="outlined"
                style={{ position: 'relative' }}
              >
                <AlertTitle>
                  &nbsp;&nbsp;{t('Remote OpenCTI configuration')}{' '}
                  {isStreamAccessible ? (
                    <CheckCircleOutlined
                      style={{ fontSize: 22, color: '#4caf50', float: 'left' }}
                    />
                  ) : (
                    <WarningOutlined
                      style={{ fontSize: 22, color: '#f44336', float: 'left' }}
                    />
                  )}
                </AlertTitle>
                <Tooltip
                  title={t(
                    'You need to configure a valid remote OpenCTI. Token is optional to consume public streams',
                  )}
                >
                  <InformationOutline
                    fontSize="small"
                    color="primary"
                    style={{ position: 'absolute', top: 10, right: 18 }}
                  />
                </Tooltip>
                <Field
                  component={TextField}
                  variant="standard"
                  name="uri"
                  label={t('Remote OpenCTI URL')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                  disabled={true}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="token"
                  label={t('Remote OpenCTI token')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                  disabled={true}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="dd"
                  label={t('Remote OpenCTI stream ID')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                  value={
                    streams.find((s) => s.id === initialValues.stream_id)
                      ?.label ?? '-'
                  }
                  disabled={true}
                />
              </Alert>
              <CreatorField
                name={'user_id'}
                label={t('User responsible for data creation (empty = System)')}
                containerStyle={fieldSpacingContainerStyle}
                onChange={handleSubmitField}
              />
              <Field
                component={DateTimePickerField}
                name="current_state_date"
                onSubmit={handleSubmitField}
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
                onChange={handleSubmitField}
              />
              <Field
                component={SwitchField}
                type="checkbox"
                name="no_dependencies"
                label={t('Avoid dependencies resolution')}
                onChange={handleSubmitField}
              />
              <Field
                component={SwitchField}
                type="checkbox"
                name="ssl_verify"
                label={t('Verify SSL certificate')}
                onChange={handleSubmitField}
              />
              <div className={classes.buttons}>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={() => handleVerify(values)}
                  classes={{ root: classes.button }}
                >
                  {t('Verify')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      </div>
    </div>
  );
};

const SyncEditionFragment = createFragmentContainer(SyncEditionContainer, {
  synchronizer: graphql`
    fragment SyncEdition_synchronizer on Synchronizer {
      id
      name
      uri
      token
      stream_id
      listen_deletion
      no_dependencies
      current_state_date
      ssl_verify
      user {
        id
        name
      }
    }
  `,
});

export default SyncEditionFragment;
