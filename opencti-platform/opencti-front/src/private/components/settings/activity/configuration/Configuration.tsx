/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { FunctionComponent } from 'react';
import * as R from 'ramda';
import { Form, Formik } from 'formik';
import { graphql, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@common/button/IconButton';
import List from '@mui/material/List';
import Grid from '@mui/material/Grid';
import { Delete } from '@mui/icons-material';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import Alert from '@mui/material/Alert';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import { useTheme } from '@mui/styles';
import { ListItemButton } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import ActivityMenu from '../../ActivityMenu';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import CreatorField from '../../../common/form/CreatorField';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import { ConfigurationQuery } from './__generated__/ConfigurationQuery.graphql';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import ItemIcon from '../../../../../components/ItemIcon';
import GroupField from '../../../common/form/GroupField';
import ObjectOrganizationField from '../../../common/form/ObjectOrganizationField';
import EnterpriseEdition from '../../../common/entreprise_edition/EnterpriseEdition';
import Breadcrumbs from '../../../../../components/Breadcrumbs';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { SETTINGS_SECURITYACTIVITY } from '../../../../../utils/hooks/useGranted';
import Security from '../../../../../utils/Security';
import useConnectedDocumentModifier from '../../../../../utils/hooks/useConnectedDocumentModifier';
import { FieldOption } from '../../../../../utils/field';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  alert: {
    width: '100%',
    marginBottom: 20,
  },
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
  paper: {
    marginTop: theme.spacing(1),
    padding: 20,
    borderRadius: 4,
  },
}));

export const configurationQuery = graphql`
  query ConfigurationQuery {
    settings {
      id
      platform_enterprise_edition {
        license_validated
      }
      activity_listeners {
        id
        name
        entity_type
      }
    }
  }
`;

export const configurationFieldPatch = graphql`
  mutation ConfigurationFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        activity_listeners {
          id
          name
          entity_type
        }
      }
    }
  }
`;

interface ConfigurationComponentProps {
  queryRef: PreloadedQuery<ConfigurationQuery>;
}

const ConfigurationComponent: FunctionComponent<
  ConfigurationComponentProps
> = ({ queryRef }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Configuration | Activity | Settings'));
  const [commit] = useApiMutation(configurationFieldPatch);
  const { settings } = usePreloadedQuery<ConfigurationQuery>(
    configurationQuery,
    queryRef,
  );
  const currentListeners = (settings.activity_listeners ?? []).map((a) => a.id);
  const onChangeData = (resetForm: () => void) => {
    return (name: string, data: FieldOption) => {
      if (!currentListeners.includes(data.value)) {
        const value = R.uniq([...currentListeners, data.value]);
        commit({
          variables: {
            id: settings?.id,
            input: { key: 'activity_listeners_ids', value },
          },
        });
      }
      resetForm();
    };
  };
  if (!settings.platform_enterprise_edition.license_validated) {
    return <EnterpriseEdition feature={t_i18n('Activity')} />;
  }
  return (
    <div data-testid="configuration-page">
      <Security
        needs={[SETTINGS_SECURITYACTIVITY]}
        placeholder={(
          <span>{t_i18n(
            'You do not have any access to the audit activity of this OpenCTI instance.',
          )}
          </span>
        )}
      >
        <div className={classes.container}>
          <ActivityMenu />
          <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Activity') }, { label: t_i18n('Configuration'), current: true }]} />
          <Grid container={true} spacing={3}>
            <Grid item xs={12}>
              <Typography variant="h4" gutterBottom={true}>
                {t_i18n('Extended activity logging')}
              </Typography>
              <Paper classes={{ root: classes.paper }} variant="outlined">
                <Alert
                  icon={false}
                  classes={{ root: classes.alert, message: classes.message }}
                  severity="info"
                  variant="outlined"
                  style={{ position: 'relative' }}
                >
                  {t_i18n(
                    'Extended activity logging can be enabled on users, groups and organizations to log their actions like reading, uploading, downloading, etc.',
                  )}
                </Alert>
                <div>
                  <Formik
                    onSubmit={() => {}}
                    enableReinitialize={true}
                    initialValues={{ users: '', groups: '', organizations: '' }}
                  >
                    {({ resetForm }) => {
                      return (
                        <Form style={{ margin: `${theme.spacing(1)} 0` }}>
                          <Grid container={true} spacing={0}>
                            <Grid
                              key="users"
                              item
                              xs={4}
                              style={{ padding: 4 }}
                            >
                              <CreatorField
                                name="users"
                                label={t_i18n('Add a user')}
                                onChange={onChangeData(resetForm)}
                                containerStyle={{ width: '100%' }}
                              />
                            </Grid>
                            <Grid
                              key="groups"
                              item
                              xs={4}
                              style={{ padding: 4 }}
                            >
                              <GroupField
                                name="groups"
                                label={t_i18n('Add a group')}
                                multiple={false}
                                onChange={onChangeData(resetForm)}
                              />
                            </Grid>
                            <Grid
                              key="organizations"
                              item
                              xs={4}
                              style={{ padding: 4 }}
                            >
                              <ObjectOrganizationField
                                alert={false}
                                name="organizations"
                                label={t_i18n('Add an organization')}
                                multiple={false}
                                onChange={onChangeData(resetForm)}
                                style={{ width: '100' }}
                              />
                            </Grid>
                          </Grid>
                        </Form>
                      );
                    }}
                  </Formik>
                </div>
                <List
                  component="nav"
                  aria-labelledby="nested-list-subheader"
                  className={classes.root}
                >
                  {(settings.activity_listeners ?? []).map((listener) => {
                    return (
                      <React.Fragment key={listener.id}>
                        <ListItem
                          divider={true}
                          secondaryAction={(
                            <IconButton
                              aria-label="Kill"
                              onClick={() => {
                                const value = currentListeners.filter(
                                  (c) => c !== listener.id,
                                );
                                commit({
                                  variables: {
                                    id: settings?.id,
                                    input: { key: 'activity_listeners_ids', value },
                                  },
                                });
                              }}
                            >
                              <Delete />
                            </IconButton>
                          )}
                        >
                          <ListItemButton
                            classes={{ root: classes.item }}
                          >
                            <ListItemIcon classes={{ root: classes.itemIcon }}>
                              <ItemIcon type={listener.entity_type} />
                            </ListItemIcon>
                            <ListItemText
                              primary={(
                                <div>
                                  <div className={classes.name}>{listener.name}</div>
                                </div>
                              )}
                            />
                          </ListItemButton>
                        </ListItem>
                      </React.Fragment>
                    );
                  })}
                </List>
              </Paper>
            </Grid>
          </Grid>
        </div>
      </Security>
    </div>
  );
};

const Configuration = () => {
  const queryRef = useQueryLoading<ConfigurationQuery>(configurationQuery, {});
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <ConfigurationComponent queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default Configuration;
