import React, { useEffect, useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Typography from '@mui/material/Typography';
import { CheckCircleOutlined, WarningOutlined } from '@mui/icons-material';
import * as Yup from 'yup';
import Button from '@common/button/Button';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import AccordionDetails from '@mui/material/AccordionDetails';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SwitchField from '../../../../components/fields/SwitchField';
import { syncCheckMutation, syncStreamCollectionQuery } from './SyncCreation';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { buildDate } from '../../../../utils/Time';
import CreatorField from '../../common/form/CreatorField';
import { isNotEmptyField } from '../../../../utils/utils';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { Accordion, AccordionSummary } from '../../../../components/Accordion';
import PasswordTextField from '../../../../components/PasswordTextField';
import { extractToken } from '../../../../utils/ingestionAuthentificationUtils';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
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
  name: Yup.string().trim().required(t('This field is required')),
  uri: Yup.string().trim().required(t('This field is required')),
  token: Yup.string(),
  stream_id: Yup.string().trim().required(t('This field is required')),
  current_state_date: Yup.date()
    .nullable()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  listen_deletion: Yup.bool(),
  no_dependencies: Yup.bool(),
  ssl_verify: Yup.bool(),
  synchronized: Yup.bool(),
  user_id: Yup.mixed().nullable(),
});

const SyncEditionContainer = ({ synchronizer }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const [streams, setStreams] = useState([]);
  const [openOptions, setOpenOptions] = useState(synchronizer.no_dependencies || synchronizer.synchronized);
  const relatedUser = synchronizer.user
    ? { label: synchronizer.user.name, value: synchronizer.user.id }
    : '';

  const initialValues = {
    name: synchronizer.name,
    uri: synchronizer.uri,
    token: extractToken(synchronizer.token),
    stream_id: synchronizer.stream_id,
    listen_deletion: synchronizer.listen_deletion,
    no_dependencies: synchronizer.no_dependencies,
    ssl_verify: synchronizer.ssl_verify,
    synchronized: synchronizer.synchronized,
    current_state_date: buildDate(synchronizer.current_state_date),
    user_id: relatedUser,
  };

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
          MESSAGING$.notifySuccess(t_i18n('Connection successfully verified'));
        }
      },
    });
  };

  const handleSubmitField = (name, value) => {
    const parsedValue = name === 'user_id' ? value.value : value;
    syncValidation(t_i18n)
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
    handleGetStreams(initialValues);
  }, []);

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={syncValidation(t_i18n)}
    >
      {({ values }) => (
        <Form>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
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
              &nbsp;&nbsp;{t_i18n('Remote OpenCTI configuration')}{' '}
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
              title={t_i18n(
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
              label={t_i18n('Remote OpenCTI URL')}
              fullWidth={true}
              style={{ marginTop: 20 }}
              disabled={true}
            />
            <PasswordTextField
              name="token"
              label={t_i18n('token')}
              disabled={true}
              isSecret
            />
            <Field
              component={TextField}
              variant="standard"
              name="dd"
              label={t_i18n('Remote OpenCTI stream ID')}
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
            name="user_id"
            label={t_i18n('User responsible for data creation (empty = System)')}
            containerStyle={fieldSpacingContainerStyle}
            onChange={handleSubmitField}
            showConfidence
          />
          <Field
            component={DateTimePickerField}
            name="current_state_date"
            onSubmit={handleSubmitField}
            textFieldProps={{
              label: t_i18n('Starting synchronization (empty = from start)'),
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
            label={t_i18n('Take deletions into account')}
            onChange={handleSubmitField}
          />
          <Field
            component={SwitchField}
            type="checkbox"
            name="ssl_verify"
            label={t_i18n('Verify SSL certificate')}
            containerstyle={{ marginBottom: 20 }}
            onChange={handleSubmitField}
          />
          <Accordion expanded={openOptions} onChange={() => setOpenOptions(!openOptions)}>
            <AccordionSummary id="accordion-panel">
              <Typography>{t_i18n('Advanced options')}</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Alert
                icon={false}
                classes={{ root: classes.alert, message: classes.message }}
                severity="error"
                variant="outlined"
                style={{ position: 'relative' }}
              >
                <div>{t_i18n('Use these options if you know what you are doing')}</div>
              </Alert>
              <Field
                component={SwitchField}
                containerstyle={{ marginTop: 20 }}
                type="checkbox"
                name="no_dependencies"
                label={t_i18n('Avoid dependencies resolution')}
                onChange={handleSubmitField}
              />
              <div>{t_i18n('Use this option if you want to prevent any built in relations resolutions (references like createdBy will still be auto resolved)')}</div>
              <hr style={{ marginTop: 20, marginBottom: 20 }} />
              <Field
                component={SwitchField}
                type="checkbox"
                containerstyle={{ marginLeft: 2 }}
                name="synchronized"
                label={t_i18n('Use perfect synchronization')}
                onChange={handleSubmitField}
              />
              <div>{t_i18n('Use this option only in case of platform to platform replication')}</div>
              <div>{t_i18n('Every data fetched from this synchronizer will be written as the only source of truth')}</div>
            </AccordionDetails>
          </Accordion>
          <div className={classes.buttons}>
            <Button
              color="secondary"
              onClick={() => handleVerify(values)}
              classes={{ root: classes.button }}
            >
              {t_i18n('Verify')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
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
      synchronized
      user {
        id
        name
      }
    }
  `,
});

export default SyncEditionFragment;
