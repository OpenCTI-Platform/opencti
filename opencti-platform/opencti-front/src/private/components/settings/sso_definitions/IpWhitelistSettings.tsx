import React, { Suspense, useEffect, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Grid from '@mui/material/Grid';
import Alert from '@mui/material/Alert';
import Chip from '@mui/material/Chip';
import { DialogActions } from '@mui/material';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { groupSetDefaultGroupForIngestionUsersQuery } from '@components/settings/groups/GroupSetDefaultGroupForIngestionUsers';
import SwitchField from '../../../../components/fields/SwitchField';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useAuth from '../../../../utils/hooks/useAuth';
import Card from '../../../../components/common/card/Card';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import { fetchQuery } from '../../../../relay/environment';
import { MESSAGING$ } from '../../../../relay/environment';
import { FieldOption } from '../../../../utils/field';
import { IpWhitelistSettingsQuery } from './__generated__/IpWhitelistSettingsQuery.graphql';
import type { GroupSetDefaultGroupForIngestionUsersQuery$data } from '@components/settings/groups/__generated__/GroupSetDefaultGroupForIngestionUsersQuery.graphql';

const ipWhitelistSettingsQuery = graphql`
  query IpWhitelistSettingsQuery {
    settings {
      id
      platform_ip_whitelist
      platform_ip_whitelist_enabled
      platform_ip_whitelist_exclusions {
        id
        name
        entity_type
      }
    }
  }
`;

const ipWhitelistSettingsMutation = graphql`
  mutation IpWhitelistSettingsMutation($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        platform_ip_whitelist
        platform_ip_whitelist_enabled
        platform_ip_whitelist_exclusions {
          id
          name
          entity_type
        }
      }
    }
  }
`;

const IpWhitelistSettingsContent = () => {
  const { t_i18n } = useFormatter();
  const { me } = useAuth();

  const data = useLazyLoadQuery<IpWhitelistSettingsQuery>(ipWhitelistSettingsQuery, {});
  const settings = data.settings;

  const [commitField] = useApiMutation(ipWhitelistSettingsMutation);

  const [localExclusions, setLocalExclusions] = useState<Array<{ id: string; name: string; entity_type: string }>>(
    (settings.platform_ip_whitelist_exclusions ?? []).map((e) => ({ id: e.id, name: e.name, entity_type: e.entity_type })),
  );
  const [exclusionsDirty, setExclusionsDirty] = useState(false);
  const [pendingRemoveExclusion, setPendingRemoveExclusion] = useState<{ id: string; name: string; reason?: 'self' | 'service_account_group' } | null>(null);
  const [serviceAccountGroupId, setServiceAccountGroupId] = useState<string | null>(null);

  const updateLocalExclusions = (newExclusions: Array<{ id: string; name: string; entity_type: string }>) => {
    setLocalExclusions(newExclusions);
    setExclusionsDirty(true);
  };

  // Fetch service account default group ID on mount
  useEffect(() => {
    fetchQuery(groupSetDefaultGroupForIngestionUsersQuery, {
      filters: {
        mode: 'and',
        filters: [{ key: ['auto_integration_assignation'], values: ['global'] }],
        filterGroups: [],
      },
    }).toPromise().then((rawData) => {
      const data = rawData as GroupSetDefaultGroupForIngestionUsersQuery$data | undefined;
      const group = data?.groups?.edges?.[0]?.node;
      if (group) {
        setServiceAccountGroupId(group.id);
      }
    }).catch(() => {});
  }, []);

  const initialValues = {
    platform_ip_whitelist: (settings.platform_ip_whitelist ?? []).join('\n'),
    platform_ip_whitelist_enabled: settings.platform_ip_whitelist_enabled ?? false,
  };

  return (
    <>
      <Grid container spacing={3} style={{ marginBottom: 20 }}>
        <Grid item xs={12}>
          <Card title={t_i18n('IP access allow list')}>
            <Formik
              onSubmit={() => {}}
              initialValues={initialValues}
              enableReinitialize={true}
            >
              {({ values, dirty, setFieldError, setFieldTouched }) => {
                const isEnabled = values.platform_ip_whitelist_enabled;
                const lines = values.platform_ip_whitelist
                  .split('\n')
                  .map((l: string) => l.trim())
                  .filter((l: string) => l.length > 0);

                const handleSaveAll = () => {
                  // Validate: if enabled, IP list must not be empty
                  if (isEnabled && lines.length === 0) {
                    setFieldTouched('platform_ip_whitelist', true, false);
                    setFieldError('platform_ip_whitelist', t_i18n('At least one IP address is required when allow list is enabled'));
                    return;
                  }

                  const ipLines = values.platform_ip_whitelist
                    .split('\n')
                    .map((l: string) => l.trim())
                    .filter((l: string) => l.length > 0);
                  const localIds = localExclusions.map((e) => e.id);
                  commitField({
                    variables: {
                      id: settings.id,
                      input: { key: 'platform_ip_whitelist_enabled', value: values.platform_ip_whitelist_enabled ? 'true' : 'false' },
                    },
                  });
                  if (values.platform_ip_whitelist_enabled) {
                    commitField({
                      variables: {
                        id: settings.id,
                        input: { key: 'platform_ip_whitelist', value: ipLines },
                      },
                    });
                    commitField({
                      variables: {
                        id: settings.id,
                        input: { key: 'platform_ip_whitelist_exclusion_ids', value: localIds },
                      },
                    });
                  } else {
                    commitField({
                      variables: {
                        id: settings.id,
                        input: { key: 'platform_ip_whitelist', value: [] },
                      },
                    });
                    commitField({
                      variables: {
                        id: settings.id,
                        input: { key: 'platform_ip_whitelist_exclusion_ids', value: [] },
                      },
                    });
                  }
                  MESSAGING$.notifySuccess(t_i18n('IP allow list configuration saved'));
                  setExclusionsDirty(false);
                };

                return (
                  <Form>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <Field
                        component={SwitchField}
                        type="checkbox"
                        name="platform_ip_whitelist_enabled"
                        label={t_i18n('Enable IP allow list')}
                        onChange={(_name: string, value: string) => {
                          if (value === 'true') {
                            const newExclusions = [...localExclusions];
                            // Add current user
                            if (!newExclusions.some((e) => e.id === me.id)) {
                              newExclusions.push({ id: me.id, name: me.name, entity_type: 'User' });
                            }
                            // Fetch and add default group for service accounts
                            fetchQuery(groupSetDefaultGroupForIngestionUsersQuery, {
                              filters: {
                                mode: 'and',
                                filters: [{ key: ['auto_integration_assignation'], values: ['global'] }],
                                filterGroups: [],
                              },
                            }).toPromise().then((rawResult) => {
                              const result = rawResult as GroupSetDefaultGroupForIngestionUsersQuery$data | undefined;
                              const group = result?.groups?.edges?.[0]?.node;
                              if (group) {
                                setServiceAccountGroupId(group.id);
                                if (!newExclusions.some((e) => e.id === group.id)) {
                                  updateLocalExclusions([...newExclusions, { id: group.id, name: group.name, entity_type: 'Group' }]);
                                } else {
                                  updateLocalExclusions(newExclusions);
                                }
                              } else {
                                updateLocalExclusions(newExclusions);
                              }
                            }).catch(() => {
                              updateLocalExclusions(newExclusions);
                            });
                          }
                        }}
                      />
                      <Button disabled={!dirty && !exclusionsDirty} onClick={handleSaveAll}>
                        {t_i18n('Save')}
                      </Button>
                    </div>

                    {isEnabled && (
                      <>
                        <Alert severity="info" variant="outlined" style={{ marginTop: 20 }}>
                          {t_i18n('Users logging in from an IP not in the allow list will be rejected.')}
                          {' '}{t_i18n('Excluded users, groups, or organizations bypass the IP check.')}
                        </Alert>
                        <Field
                          component={TextField}
                          variant="standard"
                          style={{ marginTop: 20 }}
                          name="platform_ip_whitelist"
                          label={t_i18n('Allowed IP addresses (one per line, e.g. 192.168.1.0/24)')}
                          fullWidth={true}
                          multiline={true}
                          rows={6}
                        />

                        <div style={{ marginTop: 30 }}>
                          <strong>{t_i18n('Excluded from IP check')}</strong>
                          <Formik
                            onSubmit={() => {}}
                            enableReinitialize={true}
                            initialValues={{ exclusion_member: [] }}
                          >
                            {({ setFieldValue: setExclusionFieldValue }) => (
                              <div>
                                <ObjectMembersField
                                  name="exclusion_member"
                                  label={t_i18n('Add user, group or organization')}
                                  entityTypes={['User', 'Group', 'Organization']}
                                  style={{ marginTop: 10 }}
                                  onChange={(_name: string, fieldData: FieldOption[]) => {
                                    if (fieldData && fieldData.length > 0) {
                                      const last = fieldData[fieldData.length - 1];
                                      const val = last?.value ?? '';
                                      const label = last?.label ?? val;
                                      const type = last?.type ?? 'User';
                                      if (val && !localExclusions.some((e) => e.id === val)) {
                                        updateLocalExclusions([...localExclusions, { id: val, name: label, entity_type: type }]);
                                      }
                                      // Clear the picker
                                      setExclusionFieldValue('exclusion_member', []);
                                    }
                                  }}
                                  multiple
                                />
                              </div>
                            )}
                          </Formik>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 12 }}>
                            {localExclusions.map((member) => (
                              <Chip
                                key={member.id}
                                label={`${member.name} (${member.entity_type})`}
                                onDelete={() => {
                                  if (member.id === me.id) {
                                    setPendingRemoveExclusion({ id: member.id, name: member.name, reason: 'self' });
                                  } else if (member.id === serviceAccountGroupId) {
                                    setPendingRemoveExclusion({ id: member.id, name: member.name, reason: 'service_account_group' });
                                  } else {
                                    updateLocalExclusions(localExclusions.filter((e) => e.id !== member.id));
                                  }
                                }}
                              />
                            ))}
                          </div>
                        </div>
                      </>
                    )}
                  </Form>
                );
              }}
            </Formik>
          </Card>
        </Grid>
      </Grid>
      <Dialog
        open={!!pendingRemoveExclusion}
        onClose={() => setPendingRemoveExclusion(null)}
        title={t_i18n('Remove exclusion')}
      >
        <Alert severity="warning" variant="outlined" style={{ marginBottom: 20 }}>
          {t_i18n('You are about to remove')} <strong>{pendingRemoveExclusion?.name}</strong> {t_i18n('from the IP allow list exclusion list.')}
          <br /><br />
          {pendingRemoveExclusion?.reason === 'self'
            && t_i18n('This is your own account. If your IP is not in the allow list, you will be locked out of the platform after saving.')
          }
          {pendingRemoveExclusion?.reason === 'service_account_group'
            && t_i18n('This group is currently configured as the default group for service accounts (connectors, ingestion). Removing it may block automated integrations from accessing the platform.')
          }
        </Alert>
        <DialogActions>
          <Button variant="secondary" onClick={() => setPendingRemoveExclusion(null)}>
            {t_i18n('Cancel')}
          </Button>
          <Button onClick={() => {
            if (pendingRemoveExclusion) {
              updateLocalExclusions(localExclusions.filter((e) => e.id !== pendingRemoveExclusion.id));
            }
            setPendingRemoveExclusion(null);
          }}
          >
            {t_i18n('Confirm removal')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

const IpWhitelistSettings = () => (
  <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
    <IpWhitelistSettingsContent />
  </Suspense>
);

export default IpWhitelistSettings;
