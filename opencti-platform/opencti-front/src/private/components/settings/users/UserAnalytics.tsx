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
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
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
  const { t_i18n } = useFormatter();
  const user = useFragment(UserFragment, data);
  const isEnterpriseEdition = useEnterpriseEdition();
  if (!isEnterpriseEdition) {
    return <EnterpriseEdition feature={'User activity'} />;
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
              title: t_i18n('Login to the platform'),
            }}
            dataSelection={[
              {
                date_attribute: 'created_at',
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: 'members_user',
                      values: [user.id],
                    },
                    {
                      key: 'event_scope',
                      values: ['login'],
                    },
                  ],
                  filterGroups: [],
                },
              },
            ]}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <AuditsMultiLineChart
            height={300}
            parameters={{
              title: t_i18n('Knowledge generation'),
            }}
            dataSelection={[
              {
                label: 'Create',
                date_attribute: 'created_at',
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: 'members_user',
                      values: [user.id],
                    },
                    {
                      key: 'event_scope',
                      values: ['create'],
                    },
                  ],
                  filterGroups: [],
                },
              },
              {
                label: 'Update',
                date_attribute: 'created_at',
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: 'members_user',
                      values: [user.id],
                    },
                    {
                      key: 'event_scope',
                      values: ['update'],
                    },
                  ],
                  filterGroups: [],
                },
              },
              {
                label: 'Delete',
                date_attribute: 'created_at',
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: 'members_user',
                      values: [user.id],
                    },
                    {
                      key: 'event_scope',
                      values: ['delete'],
                    },
                  ],
                  filterGroups: [],
                },
              },
            ]}
          />
        </Grid>
        <Grid item={true} xs={4} style={{ marginTop: 30 }}>
          <AuditsHorizontalBars
            height={350}
            parameters={{
              title: t_i18n('Top global search keywords'),
            }}
            dataSelection={[
              {
                attribute: 'context_data.search',
                date_attribute: 'created_at',
                number: 20,
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: 'members_user',
                      values: [user.id],
                    },
                  ],
                  filterGroups: [],
                },
              },
            ]}
          />
        </Grid>
        <Grid item={true} xs={4} style={{ marginTop: 30 }}>
          <AuditsDonut
            height={350}
            parameters={{
              title: t_i18n('Top events'),
            }}
            dataSelection={[
              {
                attribute: 'event_scope',
                date_attribute: 'created_at',
                number: 10,
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: 'members_user',
                      values: [user.id],
                    },
                    {
                      key: 'entity_type',
                      values: ['History'],
                    },
                  ],
                  filterGroups: [],
                },
              },
            ]}
          />
        </Grid>
        <Grid item={true} xs={4} style={{ marginTop: 30 }}>
          <AuditsRadar
            height={350}
            parameters={{
              title: t_i18n('Top authors of read and exported entities'),
            }}
            dataSelection={[
              {
                attribute: 'context_data.created_by_ref_id',
                date_attribute: 'created_at',
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: 'members_user',
                      values: [user.id],
                    },
                    {
                      key: 'event_scope',
                      values: ['export', 'read'],
                      operator: 'eq',
                      mode: 'or',
                    },
                  ],
                  filterGroups: [],
                },
              },
            ]}
          />
        </Grid>
        <Grid item={true} xs={8} style={{ marginTop: 30 }}>
          <AuditsList
            height={350}
            parameters={{
              title: t_i18n('Latest exports'),
            }}
            dataSelection={[
              {
                date_attribute: 'created_at',
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: 'members_user',
                      values: [user.id],
                    },
                    {
                      key: 'event_scope',
                      values: ['export'],
                    },
                  ],
                  filterGroups: [],
                },
              },
            ]}
          />
        </Grid>
        <Grid item={true} xs={4} style={{ marginTop: 30 }}>
          <AuditsHorizontalBars
            height={350}
            parameters={{
              title: t_i18n('Top read or exported entities'),
            }}
            dataSelection={[
              {
                attribute: 'context_data.id',
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: 'members_user',
                      values: [user.id],
                    },
                    {
                      key: 'event_scope',
                      values: ['export', 'read'],
                      operator: 'eq',
                      mode: 'or',
                    },
                  ],
                  filterGroups: [],
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
