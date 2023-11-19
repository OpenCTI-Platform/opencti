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
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import EnterpriseEdition from '@components/common/EnterpriseEdition';
import { UserAnalytics_user$key } from '@components/settings/users/__generated__/UserAnalytics_user.graphql';
import AuditsMultiVerticalBars from '@components/common/audits/AuditsMultiVerticalBars';
import AuditsMultiLineChart from '@components/common/audits/AuditsMultiLineChart';
import AuditsHorizontalBars from '@components/common/audits/AuditsHorizontalBars';
import AuditsDonut from '@components/common/audits/AuditsDonut';
import AuditsRadar from '@components/common/audits/AuditsRadar';
import AuditsList from '@components/common/audits/AuditsList';
import { useFormatter } from '../../../../components/i18n';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
}));

const UserFragment = graphql`
  fragment UserAnalytics_user on User {
    id
    name
    description
  }
`;

interface UserAnalyticsProps {
  data: UserAnalytics_user$key;
}

const UserAnalytics: FunctionComponent<UserAnalyticsProps> = ({ data }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const user = useFragment(UserFragment, data);
  const isEnterpriseEdition = useEnterpriseEdition();
  if (!isEnterpriseEdition) {
    return <EnterpriseEdition />;
  }
  return (
    <>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <AuditsMultiVerticalBars
            height={300}
            parameters={{
              title: t('Login to the platform'),
            }}
            dataSelection={[
              {
                date_attribute: 'created_at',
                filters: {
                  members_user: [
                    {
                      id: user.id,
                      value: user.name,
                    },
                  ],
                  event_scope: [
                    {
                      id: 'login',
                      value: 'login',
                    },
                  ],
                },
              },
            ]}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <AuditsMultiLineChart
            height={300}
            parameters={{
              title: t('Knowledge generation'),
            }}
            dataSelection={[
              {
                label: 'Create',
                date_attribute: 'created_at',
                filters: {
                  members_user: [
                    {
                      id: user.id,
                      value: user.name,
                    },
                  ],
                  event_scope: [
                    {
                      id: 'create',
                      value: 'create',
                    },
                  ],
                },
              },
              {
                label: 'Update',
                date_attribute: 'created_at',
                filters: {
                  members_user: [
                    {
                      id: user.id,
                      value: user.name,
                    },
                  ],
                  event_scope: [
                    {
                      id: 'update',
                      value: 'update',
                    },
                  ],
                },
              },
              {
                label: 'Delete',
                date_attribute: 'created_at',
                filters: {
                  members_user: [
                    {
                      id: user.id,
                      value: user.name,
                    },
                  ],
                  event_scope: [
                    {
                      id: 'delete',
                      value: 'delete',
                    },
                  ],
                },
              },
            ]}
          />
        </Grid>
        <Grid item={true} xs={4} style={{ marginTop: 30 }}>
          <AuditsHorizontalBars
            height={350}
            parameters={{
              title: t('Top global search keywords'),
            }}
            dataSelection={[
              {
                attribute: 'context_data.search',
                date_attribute: 'created_at',
                number: 20,
                filters: {
                  members_user: [
                    {
                      id: user.id,
                      value: user.name,
                    },
                  ],
                },
              },
            ]}
          />
        </Grid>
        <Grid item={true} xs={4} style={{ marginTop: 30 }}>
          <AuditsDonut
            height={350}
            parameters={{
              title: t('Top events'),
            }}
            dataSelection={[
              {
                attribute: 'event_scope',
                date_attribute: 'created_at',
                number: 10,
                filters: {
                  members_user: [
                    {
                      id: user.id,
                      value: user.name,
                    },
                  ],
                  entity_type: [
                    {
                      id: 'History',
                      value: 'Historic (knowledge)',
                    },
                  ],
                },
              },
            ]}
          />
        </Grid>
        <Grid item={true} xs={4} style={{ marginTop: 30 }}>
          <AuditsRadar
            height={350}
            parameters={{
              title: t('Top authors of read and exported entities'),
            }}
            dataSelection={[
              {
                attribute: 'context_data.created_by_ref_id',
                date_attribute: 'created_at',
                filters: {
                  members_user: [
                    {
                      id: user.id,
                      value: user.name,
                    },
                  ],
                  event_scope: [
                    {
                      id: 'export',
                      value: 'export',
                    },
                    {
                      id: 'read',
                      value: 'read',
                    },
                  ],
                },
              },
            ]}
          />
        </Grid>
        <Grid item={true} xs={8} style={{ marginTop: 30 }}>
          <AuditsList
            height={350}
            parameters={{
              title: t('Latest exports'),
            }}
            dataSelection={[
              {
                date_attribute: 'created_at',
                filters: {
                  members_user: [
                    {
                      id: user.id,
                      value: user.name,
                    },
                  ],
                  event_scope: [
                    {
                      id: 'export',
                      value: 'export',
                    },
                  ],
                },
              },
            ]}
          />
        </Grid>
        <Grid item={true} xs={4} style={{ marginTop: 30 }}>
          <AuditsHorizontalBars
            height={350}
            parameters={{
              title: t('Top read or exported entities'),
            }}
            dataSelection={[
              {
                attribute: 'context_data.id',
                filters: {
                  members_user: [
                    {
                      id: user.id,
                      value: user.name,
                    },
                  ],
                  event_scope: [
                    {
                      id: 'export',
                      value: 'export',
                    },
                    {
                      id: 'read',
                      value: 'read',
                    },
                  ],
                },
                number: 20,
              },
            ]}
          />
        </Grid>
      </Grid>
    </>
  );
};

export default UserAnalytics;
