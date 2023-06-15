/*
Copyright (c) 2021-2023 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
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
import {
  graphql,
  usePreloadedQuery,
  useMutation,
  PreloadedQuery,
} from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@mui/material/IconButton';
import List from '@mui/material/List';
import Grid from '@mui/material/Grid';
import ListItem from '@mui/material/ListItem';
import { Delete } from '@mui/icons-material';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Alert from '@mui/material/Alert';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import ActivityMenu from '../../ActivityMenu';
import { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import CreatorField from '../../../common/form/CreatorField';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import { ConfigurationQuery } from './__generated__/ConfigurationQuery.graphql';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import ItemIcon from '../../../../../components/ItemIcon';
import GroupField from '../../../common/form/GroupField';
import ObjectOrganizationField from '../../../common/form/ObjectOrganizationField';
import { Option } from '../../../common/form/ReferenceField';
import { isEmptyField } from '../../../../../utils/utils';
import EnterpriseEdition from '../../../common/EnterpriseEdition';

const useStyles = makeStyles<Theme>(() => ({
  alert: {
    width: '100%',
    marginBottom: 20,
  },
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 20,
    borderRadius: 6,
  },
}));

export const configurationQuery = graphql`
  query ConfigurationQuery {
    settings {
      id
      enterprise_edition
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
  const { t } = useFormatter();
  const [commit] = useMutation(configurationFieldPatch);
  const { settings } = usePreloadedQuery<ConfigurationQuery>(
    configurationQuery,
    queryRef,
  );
  const currentListeners = (settings.activity_listeners ?? []).map((a) => a.id);
  const onChangeData = (resetForm: () => void) => {
    return (name: string, data: Option) => {
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

  if (isEmptyField(settings.enterprise_edition)) {
    return <EnterpriseEdition />;
  }

  return (
    <div className={classes.container}>
      <ActivityMenu />
      <Grid container={true} spacing={3}>
        <Grid item={true} xs={6}>
          <Typography variant="h4" gutterBottom={true}>
            {t('Extended activity logging')}
          </Typography>
          <Paper classes={{ root: classes.paper }} variant="outlined">
            <Alert
              icon={false}
              classes={{ root: classes.alert, message: classes.message }}
              severity="info"
              variant="outlined"
              style={{ position: 'relative' }}
            >
              {t(
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
                    <Form style={{ margin: '20px 0 20px 0' }}>
                      <Grid container={true} spacing={0}>
                        <Grid
                          key="users"
                          item={true}
                          xs={4}
                          style={{ padding: 4 }}
                        >
                          <CreatorField
                            name="users"
                            label={t('Add a user')}
                            onChange={onChangeData(resetForm)}
                            containerStyle={{ width: '100%' }}
                          />
                        </Grid>
                        <Grid
                          key="groups"
                          item={true}
                          xs={4}
                          style={{ padding: 4 }}
                        >
                          <GroupField
                            name="groups"
                            label={t('Add a group')}
                            multiple={false}
                            onChange={onChangeData(resetForm)}
                            containerStyle={{ width: '100%' }}
                          />
                        </Grid>
                        <Grid
                          key="organizations"
                          item={true}
                          xs={4}
                          style={{ padding: 4 }}
                        >
                          <ObjectOrganizationField
                            alert={false}
                            name="orgs"
                            label={t('Add an organization')}
                            multiple={false}
                            onChange={onChangeData(resetForm)}
                            containerStyle={{ width: '100' }}
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
                  <div key={listener.id}>
                    <ListItem
                      classes={{ root: classes.item }}
                      divider={true}
                      button={true}
                    >
                      <ListItemIcon classes={{ root: classes.itemIcon }}>
                        <ItemIcon type={listener.entity_type} />
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <div>
                            <div className={classes.name}>{listener.name}</div>
                          </div>
                        }
                      />
                      <ListItemSecondaryAction>
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
                          size="large"
                        >
                          <Delete />
                        </IconButton>
                      </ListItemSecondaryAction>
                    </ListItem>
                  </div>
                );
              })}
            </List>
          </Paper>
        </Grid>
      </Grid>
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
