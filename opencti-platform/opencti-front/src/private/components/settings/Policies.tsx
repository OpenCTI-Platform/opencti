import React, { FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import Grid from '@mui/material/Grid';
import { makeStyles } from '@mui/styles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Alert from '@mui/material/Alert';
import MenuItem from '@mui/material/MenuItem';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { VpnKeyOutlined } from '@mui/icons-material';
import ListItemText from '@mui/material/ListItemText';
import EEChip from '@components/common/entreprise_edition/EEChip';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import DialogTitle from '@mui/material/DialogTitle';
import DangerZoneBlock from '@components/common/dangerZone/DangerZoneBlock';
import AccessesMenu from './AccessesMenu';
import ObjectOrganizationField from '../common/form/ObjectOrganizationField';
import { useFormatter } from '../../../components/i18n';
import { Option } from '../common/form/ReferenceField';
import SwitchField from '../../../components/fields/SwitchField';
import TextField from '../../../components/TextField';
import { Policies$key } from './__generated__/Policies.graphql';
import MarkdownField from '../../../components/fields/MarkdownField';
import { PoliciesQuery } from './__generated__/PoliciesQuery.graphql';
import SelectField from '../../../components/fields/SelectField';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../components/Loader';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import ItemBoolean from '../../../components/ItemBoolean';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useSensitiveModifications from '../../../utils/hooks/useSensitiveModifications';
import Transition from '../../../components/Transition';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
  paper: {
    margin: '10px 0 0 0',
    padding: 20,
    borderRadius: 4,
  },
}));

const PoliciesFragment = graphql`
  fragment Policies on Settings {
    id
    platform_login_message
    platform_consent_message
    platform_consent_confirm_text
    platform_banner_level
    platform_banner_text
    password_policy_min_length
    password_policy_max_length
    password_policy_min_symbols
    password_policy_min_numbers
    password_policy_min_words
    password_policy_min_lowercase
    password_policy_min_uppercase
    platform_providers {
      name
      strategy
    }
    platform_organization {
      id
      name
    }
    otp_mandatory
  }
`;

const policiesQuery = graphql`
  query PoliciesQuery {
    settings {
      ...Policies
    }
  }
`;

export const policiesFieldPatch = graphql`
  mutation PoliciesFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        ...Policies
      }
    }
  }
`;

const policiesValidation = () => Yup.object().shape({
  platform_organization: Yup.object().nullable(),
  otp_mandatory: Yup.boolean(),
  password_policy_min_length: Yup.number(),
  password_policy_max_length: Yup.number(),
  password_policy_min_symbols: Yup.number(),
  password_policy_min_numbers: Yup.number(),
  password_policy_min_words: Yup.number(),
  password_policy_min_lowercase: Yup.number(),
  password_policy_min_uppercase: Yup.number(),
  platform_login_message: Yup.string().nullable(),
  platform_consent_message: Yup.string().nullable(),
  platform_consent_confirm_text: Yup.string().nullable(),
  platform_banner_level: Yup.string().nullable(),
  platform_banner_text: Yup.string().nullable(),
});

interface PoliciesComponentProps {
  keyword?: string;
  queryRef: PreloadedQuery<PoliciesQuery>;
}

const PoliciesComponent: FunctionComponent<PoliciesComponentProps> = ({
  queryRef,
}) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { isSensitiveModificationEnabled, isAllowed } = useSensitiveModifications();
  const [openPlatformOrganizationChanges, setOpenPlatformOrganizationChanges] = useState<boolean>(false);

  const data = usePreloadedQuery(policiesQuery, queryRef);
  const settings = useFragment<Policies$key>(PoliciesFragment, data.settings);
  const [platformOrganization, setPlatformOrganization] = useState(
    settings.platform_organization
      ? {
        label: settings.platform_organization?.name,
        value: settings.platform_organization?.id,
      }
      : null,
  );

  const [commitField] = useApiMutation(policiesFieldPatch);
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const handleSubmitField = (name: string, value: string | string[] | Option | null) => {
    policiesValidation()
      .validateAt(name, { [name]: value })
      .then(() => {
        commitField({
          variables: {
            id: settings.id,
            input: {
              key: name,
              value: ((value as Option)?.value ?? value) || '',
            },
          },
        });
      })
      .catch(() => false);
  };
  const initialValues = {
    platform_organization: platformOrganization,
    platform_login_message: settings.platform_login_message,
    platform_consent_message: settings.platform_consent_message,
    platform_consent_confirm_text: settings.platform_consent_confirm_text,
    password_policy_min_length: settings.password_policy_min_length,
    password_policy_max_length: settings.password_policy_max_length,
    password_policy_min_symbols: settings.password_policy_min_symbols,
    password_policy_min_numbers: settings.password_policy_min_numbers,
    password_policy_min_words: settings.password_policy_min_words,
    password_policy_min_lowercase: settings.password_policy_min_lowercase,
    password_policy_min_uppercase: settings.password_policy_min_uppercase,
    platform_banner_level: settings.platform_banner_level,
    platform_banner_text: settings.platform_banner_text,
    otp_mandatory: settings.otp_mandatory,
  };
  const authProviders = settings.platform_providers;
  return (
    <div className={classes.container}>
      <AccessesMenu />
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Security') }, { label: t_i18n('Policies'), current: true }]} />
      <Grid container={true} spacing={3}>
        <Grid item xs={12}>
          <Formik
            onSubmit={() => {
            }}
            initialValues={initialValues}
            enableReinitialize={true}
            validationSchema={policiesValidation()}
          >
            {({ values, setFieldValue }) => (
              <Form>
                <Grid container={true} spacing={3}>
                  <Grid item xs={6}>
                    <DangerZoneBlock
                      title={(
                        <>
                          {t_i18n('Platform main organization')} <EEChip />
                        </>
                      )}
                      component={({ disabled, style }) => (
                        <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined" style={style}>
                          <Alert severity="warning" variant="outlined">
                            {t_i18n(
                              'When you set a platform organization, all the pieces of knowledge which are not shared with any organization will be accessible only for users part of the platform one.',
                            )}
                          </Alert>
                          <EETooltip>
                            <ObjectOrganizationField
                              name="platform_organization"
                              disabled={disabled || !isEnterpriseEdition || (isSensitiveModificationEnabled && !isAllowed)}
                              label={'Platform organization'}
                              onChange={() => setOpenPlatformOrganizationChanges(true)}
                              style={{ width: '100%', marginTop: 20 }}
                              multiple={false}
                              outlined={false}
                            />
                          </EETooltip>
                          <Dialog
                            PaperProps={{ elevation: 1 }}
                            open={openPlatformOrganizationChanges}
                            keepMounted
                            TransitionComponent={Transition}
                            onClose={() => setOpenPlatformOrganizationChanges(false)}
                          >
                            <DialogTitle>{t_i18n('Warning')}</DialogTitle>
                            <DialogContent>
                              <DialogContentText>
                                <Alert severity="warning" variant="filled" color="dangerZone">
                                  {t_i18n(
                                    'This change may have an impact on users and connectors who WILL NO LONGER BE ABLE TO ACCESS KNOWLEDGE if they do not belong to the main platform organization.',
                                  )}
                                </Alert>
                              </DialogContentText>
                            </DialogContent>
                            <DialogActions>
                              <Button
                                onClick={() => {
                                  setFieldValue('platform_organization', platformOrganization);
                                  setOpenPlatformOrganizationChanges(false);
                                }}
                              >
                                {t_i18n('Cancel')}
                              </Button>
                              <Button
                                color="secondary"
                                onClick={() => {
                                  setPlatformOrganization(values.platform_organization);
                                  setOpenPlatformOrganizationChanges(false);
                                  handleSubmitField('platform_organization', values.platform_organization);
                                }}
                              >
                                {t_i18n('Validate')}
                              </Button>
                            </DialogActions>
                          </Dialog>
                        </Paper>
                      )}
                    />
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t_i18n('Authentication strategies')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
                      <List style={{ marginTop: -20 }}>
                        {authProviders.map((provider) => (
                          <ListItem key={provider.strategy} divider={true}>
                            <ListItemIcon>
                              <VpnKeyOutlined color="primary" />
                            </ListItemIcon>
                            <ListItemText
                              primary={provider.name}
                              secondary={provider.strategy}
                            />
                            <ItemBoolean
                              variant="inList"
                              label={t_i18n('Enabled')}
                              status={true}
                            />
                          </ListItem>
                        ))}
                      </List>
                      <Field
                        component={SwitchField}
                        type="checkbox"
                        name="otp_mandatory"
                        label={t_i18n('Enforce two-factor authentication')}
                        containerstyle={{ marginTop: 20 }}
                        onChange={(name: string, value: string) => handleSubmitField(name, value)
                        }
                        tooltip={t_i18n(
                          'When enforcing 2FA authentication, all users will be asked to enable 2FA to be able to login in the platform.',
                        )}
                      />
                    </Paper>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t_i18n('Local password policies')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
                      <Field
                        component={TextField}
                        type="number"
                        variant="standard"
                        name="password_policy_min_length"
                        label={t_i18n(
                          'Number of chars must be greater or equals to',
                        )}
                        fullWidth={true}
                        onSubmit={(name: string, value: string) => {
                          return handleSubmitField(
                            name,
                            value !== '' ? value : '0',
                          );
                        }}
                      />
                      <Field
                        component={TextField}
                        type="number"
                        variant="standard"
                        style={{ marginTop: 20 }}
                        name="password_policy_max_length"
                        label={`${t_i18n(
                          'Number of chars must be lower or equals to',
                        )} (${t_i18n('0 equals no maximum')})`}
                        fullWidth={true}
                        onSubmit={(name: string, value: string) => {
                          return handleSubmitField(
                            name,
                            value !== '' ? value : '0',
                          );
                        }}
                      />
                      <Field
                        component={TextField}
                        type="number"
                        variant="standard"
                        style={{ marginTop: 20 }}
                        name="password_policy_min_symbols"
                        label={t_i18n(
                          'Number of symbols must be greater or equals to',
                        )}
                        fullWidth={true}
                        onSubmit={(name: string, value: string) => {
                          return handleSubmitField(
                            name,
                            value !== '' ? value : '0',
                          );
                        }}
                      />
                      <Field
                        component={TextField}
                        type="number"
                        variant="standard"
                        style={{ marginTop: 20 }}
                        name="password_policy_min_numbers"
                        label={t_i18n(
                          'Number of digits must be greater or equals to',
                        )}
                        fullWidth={true}
                        onSubmit={(name: string, value: string) => {
                          return handleSubmitField(
                            name,
                            value !== '' ? value : '0',
                          );
                        }}
                      />
                      <Field
                        component={TextField}
                        type="number"
                        variant="standard"
                        style={{ marginTop: 20 }}
                        name="password_policy_min_words"
                        label={t_i18n(
                          'Number of words (split on hyphen, space) must be greater or equals to',
                        )}
                        fullWidth={true}
                        onSubmit={(name: string, value: string) => {
                          return handleSubmitField(
                            name,
                            value !== '' ? value : '0',
                          );
                        }}
                      />
                      <Field
                        component={TextField}
                        type="number"
                        variant="standard"
                        style={{ marginTop: 20 }}
                        name="password_policy_min_lowercase"
                        label={t_i18n(
                          'Number of lowercase chars must be greater or equals to',
                        )}
                        fullWidth={true}
                        onSubmit={(name: string, value: string) => {
                          return handleSubmitField(
                            name,
                            value !== '' ? value : '0',
                          );
                        }}
                      />
                      <Field
                        component={TextField}
                        type="number"
                        variant="standard"
                        style={{ marginTop: 20 }}
                        name="password_policy_min_uppercase"
                        label={t_i18n(
                          'Number of uppercase chars must be greater or equals to',
                        )}
                        fullWidth={true}
                        onSubmit={(name: string, value: string) => {
                          return handleSubmitField(
                            name,
                            value !== '' ? value : '0',
                          );
                        }}
                      />
                    </Paper>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t_i18n('Login messages')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} variant="outlined">
                      <Field
                        component={MarkdownField}
                        name="platform_login_message"
                        label={t_i18n('Platform login message')}
                        fullWidth
                        multiline={true}
                        rows="3"
                        onSubmit={handleSubmitField}
                        variant="standard"
                      />
                      <Field
                        component={MarkdownField}
                        name="platform_consent_message"
                        label={t_i18n('Platform consent message')}
                        fullWidth
                        style={{ marginTop: 20 }}
                        onSubmit={handleSubmitField}
                        variant="standard"
                      />
                      <Field
                        component={MarkdownField}
                        name="platform_consent_confirm_text"
                        label={t_i18n('Platform consent confirm text')}
                        fullWidth
                        style={{ marginTop: 20 }}
                        height={38}
                        onSubmit={handleSubmitField}
                        variant="standard"
                      />
                    </Paper>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="h4" gutterBottom={true}>
                      {t_i18n('Platform Banner Configuration')}
                    </Typography>
                    <Paper classes={{ root: classes.paper }} variant="outlined">
                      <Field
                        component={SelectField}
                        variant="standard"
                        name="platform_banner_level"
                        label={t_i18n('Platform banner level')}
                        fullWidth={true}
                        containerstyle={{ marginTop: 5, width: '100%' }}
                        onSubmit={(name: string, value: string) => {
                          return handleSubmitField(name, value);
                        }}
                        displ
                      >
                        <MenuItem value="">&nbsp;</MenuItem>
                        <MenuItem value="GREEN">{t_i18n('GREEN')}</MenuItem>
                        <MenuItem value="RED">{t_i18n('RED')}</MenuItem>
                        <MenuItem value="YELLOW">{t_i18n('YELLOW')}</MenuItem>
                      </Field>
                      <Field
                        component={TextField}
                        variant="standard"
                        style={{ marginTop: 20 }}
                        name="platform_banner_text"
                        label={t_i18n('Platform banner text')}
                        fullWidth={true}
                        onSubmit={handleSubmitField}
                      />
                    </Paper>
                  </Grid>
                </Grid>
              </Form>
            )}
          </Formik>
        </Grid>
      </Grid>
    </div>
  );
};

const Policies: FunctionComponent = () => {
  const queryRef = useQueryLoading<PoliciesQuery>(policiesQuery, {});
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <PoliciesComponent queryRef={queryRef} />
        </React.Suspense>
      )}
    </>
  );
};

export default Policies;
