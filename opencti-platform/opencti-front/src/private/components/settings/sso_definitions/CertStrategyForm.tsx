import React, { useState } from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useTheme } from '@mui/styles';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import Typography from '@mui/material/Typography';
import { ExpandMoreOutlined } from '@mui/icons-material';
import SwitchField from '../../../../components/fields/SwitchField';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';
import Button from '@common/button/Button';
import AuthProviderGroupsFields from './AuthProviderGroupsFields';
import AuthProviderOrganizationsFields from './AuthProviderOrganizationsFields';
import type { CertStrategyFormQuery } from './__generated__/CertStrategyFormQuery.graphql';
import type { CertStrategyFormMutation } from './__generated__/CertStrategyFormMutation.graphql';

const certStrategyFormQuery = graphql`
  query CertStrategyFormQuery {
    settings {
      id
      cert_auth {
        enabled
        button_label
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

const certStrategyFormMutation = graphql`
  mutation CertStrategyFormMutation($id: ID!, $input: CertAuthConfigInput!) {
    settingsEdit(id: $id) {
      updateCertAuth(input: $input) {
        id
        cert_auth {
          enabled
          button_label
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

interface CertStrategyFormValues {
  enabled: boolean;
  button_label: string;
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
  button_label: Yup.string().nullable(),
  user_info_mapping: Yup.object().shape({
    email_expr: Yup.string().required('This field is required'),
    name_expr: Yup.string().required('This field is required'),
  }),
});

interface CertStrategyFormProps {
  onCancel: () => void;
}

const CertStrategyForm = ({ onCancel }: CertStrategyFormProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [currentTab, setCurrentTab] = useState(0);

  const data = useLazyLoadQuery<CertStrategyFormQuery>(certStrategyFormQuery, {});
  const settings = data.settings;
  const certAuth = settings.cert_auth;

  const [commitMutation] = useApiMutation<CertStrategyFormMutation>(
    certStrategyFormMutation,
    undefined,
    { successMessage: t_i18n('Authentication successfully updated') },
  );

  const gm = certAuth?.groups_mapping;
  const om = certAuth?.organizations_mapping;
  const uim = certAuth?.user_info_mapping;

  const initialValues: CertStrategyFormValues = {
    enabled: certAuth?.enabled ?? false,
    button_label: certAuth?.button_label ?? '',
    user_info_mapping: {
      email_expr: uim?.email_expr ?? 'subject.emailAddress',
      name_expr: uim?.name_expr ?? 'subject.CN',
      firstname_expr: uim?.firstname_expr ?? '',
      lastname_expr: uim?.lastname_expr ?? '',
    },
    groups_mapping: {
      default_groups: [...(gm?.default_groups ?? [])],
      groups_expr: [...(gm?.groups_expr ?? ['subject.OU'])],
      group_splitter: gm?.group_splitter ?? '',
      groups_mapping: (gm?.groups_mapping ?? []).map((m) => ({ provider: m.provider, platform: m.platform })),
      auto_create_groups: gm?.auto_create_groups ?? false,
      prevent_default_groups: gm?.prevent_default_groups ?? false,
    },
    organizations_mapping: {
      default_organizations: [...(om?.default_organizations ?? [])],
      organizations_expr: [...(om?.organizations_expr ?? ['subject.O'])],
      organizations_splitter: om?.organizations_splitter ?? '',
      organizations_mapping: (om?.organizations_mapping ?? []).map((m) => ({ provider: m.provider, platform: m.platform })),
      auto_create_organizations: om?.auto_create_organizations ?? false,
    },
  };

  const handleSubmit = (
    values: CertStrategyFormValues,
    { setSubmitting }: { setSubmitting: (flag: boolean) => void },
  ) => {
    setSubmitting(true);
    commitMutation({
      variables: {
        id: settings.id,
        input: {
          enabled: values.enabled,
          button_label: values.button_label || null,
          user_info_mapping: {
            email_expr: values.user_info_mapping.email_expr,
            name_expr: values.user_info_mapping.name_expr,
            firstname_expr: values.user_info_mapping.firstname_expr || null,
            lastname_expr: values.user_info_mapping.lastname_expr || null,
          },
          groups_mapping: {
            default_groups: values.groups_mapping.default_groups.filter((s) => s.trim() !== ''),
            groups_expr: values.groups_mapping.groups_expr.filter((s) => s.trim() !== ''),
            group_splitter: values.groups_mapping.group_splitter || null,
            groups_mapping: values.groups_mapping.groups_mapping
              .filter((m) => m.provider.trim() !== '' || m.platform.trim() !== '')
              .map((m) => ({ provider: m.provider, platform: m.platform })),
            auto_create_groups: values.groups_mapping.auto_create_groups,
            prevent_default_groups: values.groups_mapping.prevent_default_groups,
          },
          organizations_mapping: {
            default_organizations: values.organizations_mapping.default_organizations.filter((s) => s.trim() !== ''),
            organizations_expr: values.organizations_mapping.organizations_expr.filter((s) => s.trim() !== ''),
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
                label={t_i18n('Enable client certificate authentication')}
                containerstyle={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="user_info_mapping.email_expr"
                label={t_i18n('Email attribute')}
                placeholder="subject.emailAddress"
                required
                fullWidth
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="user_info_mapping.name_expr"
                label={t_i18n('Name attribute')}
                placeholder="subject.CN"
                required
                fullWidth
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="user_info_mapping.firstname_expr"
                label={t_i18n('Firstname attribute')}
                placeholder={t_i18n('Leave empty if not available')}
                fullWidth
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="user_info_mapping.lastname_expr"
                label={t_i18n('Lastname attribute')}
                placeholder={t_i18n('Leave empty if not available')}
                fullWidth
                style={{ marginTop: 20 }}
              />

              {/* --- Display & Metadata --- */}
              <Accordion variant="outlined" style={{ marginTop: 20 }}>
                <AccordionSummary expandIcon={<ExpandMoreOutlined />}>
                  <Typography>{t_i18n('Display & Metadata')}</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ display: 'block', pb: 2 }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="button_label"
                    label={t_i18n('Button label')}
                    fullWidth
                    style={{ marginTop: 10 }}
                  />
                </AccordionDetails>
              </Accordion>
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

export default CertStrategyForm;
