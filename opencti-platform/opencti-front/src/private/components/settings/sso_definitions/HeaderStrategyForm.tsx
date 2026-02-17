import React, { useState } from 'react';
import { Field, FieldArray, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useTheme } from '@mui/styles';
import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Typography from '@mui/material/Typography';
import { Add, Delete } from '@mui/icons-material';
import SwitchField from '../../../../components/fields/SwitchField';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import AuthProviderGroupsFields from './AuthProviderGroupsFields';
import AuthProviderOrganizationsFields from './AuthProviderOrganizationsFields';
import AuthProviderUserInfoFields from './AuthProviderUserInfoFields';
import type { HeaderStrategyFormQuery } from './__generated__/HeaderStrategyFormQuery.graphql';
import type { HeaderStrategyFormMutation } from './__generated__/HeaderStrategyFormMutation.graphql';

const headerStrategyFormQuery = graphql`
  query HeaderStrategyFormQuery {
    settings {
      id
      headers_auth {
        enabled
        description
        logout_uri
        headers_audit
        user_info_mapping {
          email_expr
          name_expr
          firstname_expr
          lastname_expr
        }
        groups_mapping {
          default_groups
          groups_expr
          group_splitter
          groups_mapping {
            provider
            platform
          }
          auto_create_groups
          prevent_default_groups
        }
        organizations_mapping {
          default_organizations
          organizations_expr
          organizations_splitter
          organizations_mapping {
            provider
            platform
          }
          auto_create_organizations
        }
      }
    }
  }
`;

const headerStrategyFormMutation = graphql`
  mutation HeaderStrategyFormMutation($id: ID!, $input: HeadersAuthConfigInput!) {
    settingsEdit(id: $id) {
      updateHeaderAuth(input: $input) {
        id
        headers_auth {
          enabled
          description
          logout_uri
          headers_audit
          user_info_mapping {
            email_expr
            name_expr
            firstname_expr
            lastname_expr
          }
          groups_mapping {
            default_groups
            groups_expr
            group_splitter
            groups_mapping {
              provider
              platform
            }
            auto_create_groups
            prevent_default_groups
          }
          organizations_mapping {
            default_organizations
            organizations_expr
            organizations_splitter
            organizations_mapping {
              provider
              platform
            }
            auto_create_organizations
          }
        }
      }
    }
  }
`;

interface MappingEntry {
  provider: string;
  platform: string;
}

interface HeaderStrategyFormValues {
  enabled: boolean;
  description: string;
  logout_uri: string;
  headers_audit: string[];
  user_info_mapping: {
    email_expr: string;
    name_expr: string;
    firstname_expr: string;
    lastname_expr: string;
  };
  groups_mapping: {
    default_groups: string[];
    groups_expr: string[];
    group_splitter: string;
    groups_mapping: MappingEntry[];
    auto_create_groups: boolean;
    prevent_default_groups: boolean;
  };
  organizations_mapping: {
    default_organizations: string[];
    organizations_expr: string[];
    organizations_splitter: string;
    organizations_mapping: MappingEntry[];
    auto_create_organizations: boolean;
  };
}

const validationSchema = Yup.object().shape({
  enabled: Yup.boolean(),
  logout_uri: Yup.string().nullable(),
  user_info_mapping: Yup.object().shape({
    email_expr: Yup.string().required('This field is required'),
    name_expr: Yup.string().required('This field is required'),
  }),
});

interface HeaderStrategyFormProps {
  onCancel: () => void;
}

const HeaderStrategyForm = ({ onCancel }: HeaderStrategyFormProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [currentTab, setCurrentTab] = useState(0);

  const data = useLazyLoadQuery<HeaderStrategyFormQuery>(headerStrategyFormQuery, {});
  const settings = data.settings;
  const headerAuth = settings.headers_auth;

  const [commitMutation] = useApiMutation<HeaderStrategyFormMutation>(
    headerStrategyFormMutation,
    undefined,
    { successMessage: t_i18n('Authentication successfully updated') },
  );

  const gm = headerAuth?.groups_mapping;
  const om = headerAuth?.organizations_mapping;
  const uim = headerAuth?.user_info_mapping;

  const initialValues: HeaderStrategyFormValues = {
    enabled: headerAuth?.enabled ?? false,
    description: headerAuth?.description ?? '',
    logout_uri: headerAuth?.logout_uri ?? '',
    headers_audit: (headerAuth?.headers_audit ?? []).filter((s): s is string => s !== null && s !== undefined),
    user_info_mapping: {
      email_expr: uim?.email_expr ?? '',
      name_expr: uim?.name_expr ?? '',
      firstname_expr: uim?.firstname_expr ?? '',
      lastname_expr: uim?.lastname_expr ?? '',
    },
    groups_mapping: {
      default_groups: [...(gm?.default_groups ?? [])],
      groups_expr: [...(gm?.groups_expr ?? [])],
      group_splitter: gm?.group_splitter ?? '',
      groups_mapping: (gm?.groups_mapping ?? []).map((m) => ({ provider: m.provider, platform: m.platform })),
      auto_create_groups: gm?.auto_create_groups ?? false,
      prevent_default_groups: gm?.prevent_default_groups ?? false,
    },
    organizations_mapping: {
      default_organizations: [...(om?.default_organizations ?? [])],
      organizations_expr: [...(om?.organizations_expr ?? [])],
      organizations_splitter: om?.organizations_splitter ?? '',
      organizations_mapping: (om?.organizations_mapping ?? []).map((m) => ({ provider: m.provider, platform: m.platform })),
      auto_create_organizations: om?.auto_create_organizations ?? false,
    },
  };

  const filterStringArray = (arr: string[]): string[] => arr.filter((s) => s.trim() !== '');

  const handleSubmit = (
    values: HeaderStrategyFormValues,
    { setSubmitting }: { setSubmitting: (flag: boolean) => void },
  ) => {
    setSubmitting(true);
    commitMutation({
      variables: {
        id: settings.id,
        input: {
          enabled: values.enabled,
          description: values.description || null,
          logout_uri: values.logout_uri || null,
          headers_audit: filterStringArray(values.headers_audit),
          user_info_mapping: {
            email_expr: values.user_info_mapping.email_expr,
            name_expr: values.user_info_mapping.name_expr,
            firstname_expr: values.user_info_mapping.firstname_expr || null,
            lastname_expr: values.user_info_mapping.lastname_expr || null,
          },
          groups_mapping: {
            default_groups: filterStringArray(values.groups_mapping.default_groups),
            groups_expr: filterStringArray(values.groups_mapping.groups_expr),
            group_splitter: values.groups_mapping.group_splitter || null,
            groups_mapping: values.groups_mapping.groups_mapping
              .filter((m) => m.provider.trim() !== '' || m.platform.trim() !== '')
              .map((m) => ({ provider: m.provider, platform: m.platform })),
            auto_create_groups: values.groups_mapping.auto_create_groups,
            prevent_default_groups: values.groups_mapping.prevent_default_groups,
          },
          organizations_mapping: {
            default_organizations: filterStringArray(values.organizations_mapping.default_organizations),
            organizations_expr: filterStringArray(values.organizations_mapping.organizations_expr),
            organizations_splitter: values.organizations_mapping.organizations_splitter || null,
            organizations_mapping: values.organizations_mapping.organizations_mapping
              .filter((m) => m.provider.trim() !== '' || m.platform.trim() !== '')
              .map((m) => ({ provider: m.provider, platform: m.platform })),
            auto_create_organizations: values.organizations_mapping.auto_create_organizations,
          },
        },
      },
      onCompleted: () => {
        setSubmitting(false);
        onCancel();
      },
      onError: () => {
        setSubmitting(false);
      },
    });
  };

  return (
    <Formik
      enableReinitialize
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={handleSubmit}
      onReset={onCancel}
    >
      {({ handleReset, submitForm, isSubmitting }) => (
        <Form>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs value={currentTab} onChange={(_, value) => setCurrentTab(value)}>
              <Tab label={t_i18n('Configuration')} />
              <Tab label={t_i18n('Groups')} />
              <Tab label={t_i18n('Organizations')} />
            </Tabs>
          </Box>

          {/* Tab 0: Configuration */}
          {currentTab === 0 && (
            <>
              <Field
                component={SwitchField}
                type="checkbox"
                name="enabled"
                label={t_i18n('Enable header authentication')}
                containerstyle={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="description"
                label={t_i18n('Description')}
                fullWidth
                multiline
                rows={3}
                style={{ marginTop: 20 }}
              />
              <AuthProviderUserInfoFields fieldPrefix="user_info_mapping" />
              <Field
                component={TextField}
                variant="standard"
                name="logout_uri"
                label={t_i18n('Logout URI')}
                fullWidth
                style={{ marginTop: 20 }}
              />
              {/* Headers audit - multi-value list */}
              <FieldArray name="headers_audit">
                {({ push, remove, form }) => {
                  const entries = (form.values as HeaderStrategyFormValues).headers_audit;
                  return (
                    <Paper variant="outlined" sx={{ mt: 2, borderRadius: 1, overflow: 'hidden' }}>
                      <Box sx={{ px: 2, py: 1, backgroundColor: 'action.hover', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <Typography variant="h4" sx={{ m: 0 }}>{t_i18n('Headers audit')}</Typography>
                        <IconButton
                          color="primary"
                          aria-label={t_i18n('Add')}
                          size="default"
                          onClick={() => push('')}
                        >
                          <Add fontSize="small" color="primary" />
                        </IconButton>
                      </Box>
                      <Box sx={{ px: 2, pb: entries.length > 0 ? 1 : 0 }}>
                        {entries.map((_: string, index: number) => (
                          <div
                            key={index}
                            style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}
                          >
                            <Field
                              component={TextField}
                              variant="standard"
                              name={`headers_audit[${index}]`}
                              label={t_i18n('Header name')}
                              fullWidth
                            />
                            <IconButton
                              color="primary"
                              aria-label={t_i18n('Delete')}
                              onClick={() => remove(index)}
                              style={{ marginTop: 10 }}
                            >
                              <Delete fontSize="small" />
                            </IconButton>
                          </div>
                        ))}
                      </Box>
                    </Paper>
                  );
                }}
              </FieldArray>
            </>
          )}

          {/* Tab 1: Groups */}
          {currentTab === 1 && (
            <AuthProviderGroupsFields />
          )}

          {/* Tab 2: Organizations */}
          {currentTab === 2 && (
            <AuthProviderOrganizationsFields />
          )}

          {/* Shared Cancel / Update buttons */}
          <div style={{ marginTop: 20, textAlign: 'right' }}>
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
              style={{ marginLeft: theme.spacing(1) }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitForm}
              disabled={isSubmitting}
              style={{ marginLeft: theme.spacing(1) }}
            >
              {t_i18n('Update')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

export default HeaderStrategyForm;
