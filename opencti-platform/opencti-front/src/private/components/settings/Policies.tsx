import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import EEChip from '@components/common/entreprise_edition/EEChip';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import GroupSetDefaultGroupForIngestionUsers from '@components/settings/groups/GroupSetDefaultGroupForIngestionUsers';
import Alert from '@mui/material/Alert';
import Grid from '@mui/material/Grid';
import MenuItem from '@mui/material/MenuItem';
import { useTheme } from '@mui/styles';
import { Field, Form, Formik } from 'formik';
import React, { FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import * as Yup from 'yup';
import Breadcrumbs from '../../../components/Breadcrumbs';
import Card from '../../../components/common/card/Card';
import MarkdownField from '../../../components/fields/MarkdownField';
import SelectField from '../../../components/fields/SelectField';
import SwitchField from '../../../components/fields/SwitchField';

import { useFormatter } from '../../../components/i18n';
import Loader, { LoaderVariant } from '../../../components/Loader';
import TextField from '../../../components/TextField';
import type { Theme } from '../../../components/Theme';
import { FieldOption } from '../../../utils/field';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import useHelper from '../../../utils/hooks/useHelper';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import DangerZoneBlock from '../common/danger_zone/DangerZoneBlock';
import ObjectOrganizationField from '../common/form/ObjectOrganizationField';
import { Policies$key } from './__generated__/Policies.graphql';
import { PoliciesQuery } from './__generated__/PoliciesQuery.graphql';
import AccessesMenu from './AccessesMenu';
import { DialogActions } from '@mui/material';

const PoliciesFragment = graphql`
  fragment Policies on Settings {
    id
    platform_login_message
    platform_consent_message
    platform_consent_confirm_text
    platform_banner_level
    platform_banner_text
    platform_organization {
      id
      name
    }
    view_all_users
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
  view_all_users: Yup.boolean(),
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
  const theme = useTheme<Theme>();
  const isEnterpriseEdition = useEnterpriseEdition();
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

  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Policies | Security | Settings'));

  const { isFeatureEnable } = useHelper();
  const isUsersVisibilityFeatureEnable = isFeatureEnable('USERS_VISIBILITY');

  const handleSubmitField = (name: string, value: string | string[] | FieldOption | null) => {
    policiesValidation()
      .validateAt(name, { [name]: value })
      .then(() => {
        commitField({
          variables: {
            id: settings.id,
            input: {
              key: name,
              value: ((value as FieldOption)?.value ?? value) || '',
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
    platform_banner_level: settings.platform_banner_level,
    platform_banner_text: settings.platform_banner_text,
    view_all_users: settings.view_all_users ?? false,
  };
  return (
    <div
      style={{
        margin: 0,
        padding: '0 200px 50px 0',
      }}
      data-testid="policies-settings-page"
    >
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
                      type="platform_organization"
                      title={<>{t_i18n('Platform main organization')} <EEChip /></>}
                      displayTitle={false}
                      component={({ disabled, style, title }) => (
                        <Card
                          title={title}
                          sx={style}
                        >
                          <Alert severity="info" variant="outlined">
                            {t_i18n('When you set a platform organization you enable the organization sharing and segregation feature.')}
                            <br />
                            {t_i18n('Therefore all pieces of knowledge which are not explicitly shared with any organization won\'t be accessible to user(s) not member of the platform organization.')}
                            <br />
                            {t_i18n('Service Account will automatically be part of the Platform Main Organization, but will not be listed in the list of users of this organisation')}
                          </Alert>
                          <EETooltip>
                            <ObjectOrganizationField
                              name="platform_organization"
                              disabled={disabled || !isEnterpriseEdition}
                              label="Platform organization"
                              onChange={() => setOpenPlatformOrganizationChanges(true)}
                              style={{ width: '100%', marginTop: 20 }}
                              multiple={false}
                              outlined={false}
                            />
                          </EETooltip>
                          <Dialog
                            open={openPlatformOrganizationChanges}
                            keepMounted
                            onClose={() => setOpenPlatformOrganizationChanges(false)}
                            title={t_i18n('Numerous repercussions linked to the activation of this feature')}
                          >
                            <Alert
                              severity="warning"
                              variant="outlined"
                              color="dangerZone"
                              style={{
                                borderColor: theme.palette.dangerZone.main,
                              }}
                            >
                              {t_i18n(
                                'This feature has implications for the entire platform and must be fully understood before being used. For example, it\'s mandatory to have organizations set up for each user, otherwise they won\'t be able to log in. It is also mandatory to include connector\'s users in the platform main organization to avoid import problems.',
                              )}
                            </Alert>

                            <DialogActions>
                              <Button
                                variant="secondary"
                                onClick={() => {
                                  setFieldValue('platform_organization', platformOrganization);
                                  setOpenPlatformOrganizationChanges(false);
                                }}
                              >
                                {t_i18n('Cancel')}
                              </Button>
                              <Button
                                onClick={() => {
                                  setPlatformOrganization(values.platform_organization);
                                  setOpenPlatformOrganizationChanges(false);
                                  handleSubmitField('platform_organization', values.platform_organization);
                                  if (values.platform_organization) {
                                    setFieldValue('view_all_users', false);
                                    handleSubmitField('view_all_users', 'false');
                                  }
                                }}
                              >
                                {t_i18n('Validate')}
                              </Button>
                            </DialogActions>
                          </Dialog>
                        </Card>
                      )}
                    />
                  </Grid>

                  <GroupSetDefaultGroupForIngestionUsers />

                  {isUsersVisibilityFeatureEnable && (
                    <Grid item xs={6}>
                      <Card title={t_i18n('Users visibility')}>
                        <Alert severity="info" variant="outlined">
                          {t_i18n('This option is automatically disabled when a platform organization is set.')}
                        </Alert>
                        <Field
                          component={SwitchField}
                          type="checkbox"
                          name="view_all_users"
                          label={t_i18n('Allow users to view users of other organizations')}
                          containerstyle={{ marginTop: 20 }}
                          disabled={!!values.platform_organization}
                          onChange={(name: string, value: string) => handleSubmitField(name, value)}
                        />
                      </Card>
                    </Grid>
                  )}

                  <Grid item xs={6}>
                    <Card title={t_i18n('Platform Banner Configuration')}>
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
                    </Card>
                  </Grid>

                  {/* Full width: Login messages */}
                  <Grid item xs={12}>
                    <Card title={t_i18n('Login messages')}>
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
                    </Card>
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
