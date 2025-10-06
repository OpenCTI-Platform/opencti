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

import { Grid } from '@components';
import AuditsDonut from '@private/components/common/audits/AuditsDonut';
import AuditsHorizontalBars from '@private/components/common/audits/AuditsHorizontalBars';
import AuditsList from '@private/components/common/audits/AuditsList';
import AuditsMultiLineChart from '@private/components/common/audits/AuditsMultiLineChart';
import AuditsMultiVerticalBars from '@private/components/common/audits/AuditsMultiVerticalBars';
import AuditsRadar from '@private/components/common/audits/AuditsRadar';
import EnterpriseEdition from '@private/components/common/entreprise_edition/EnterpriseEdition';
import { UserAnalytics_user$key } from '@private/components/settings/users/__generated__/UserAnalytics_user.graphql';
import { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

const UserFragment = graphql`
  fragment UserAnalytics_user on User {
    id
    name
    description
    user_service_account
  }
`;

interface UserAnalyticsProps {
  data: UserAnalytics_user$key;
}

const UserAnalytics: FunctionComponent<UserAnalyticsProps> = ({ data }) => {
  const { t_i18n } = useFormatter();
  const user = useFragment(UserFragment, data);
  const userServiceAccount = user.user_service_account;
  const isEnterpriseEdition = useEnterpriseEdition();
  if (!isEnterpriseEdition) {
    return <EnterpriseEdition feature={'User activity'} />;
  }
  return (
    <>
      <Grid
        container
        rowSpacing={5}
        columnSpacing={2}
        style={{ marginBottom: 50 }}
      >
        <Grid size={6}>
          <AuditsMultiVerticalBars
            variant={undefined}
            startDate={undefined}
            endDate={undefined}
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
        <Grid size={6}>
          <AuditsMultiLineChart
            variant={undefined}
            startDate={undefined}
            endDate={undefined}
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
        {!userServiceAccount && (
        <Grid size={4}>
          <AuditsHorizontalBars
            variant={undefined}
            startDate={undefined}
            endDate={undefined}
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
        )}
        <Grid size={4}>
          <AuditsDonut
            variant={''}
            startDate={undefined}
            endDate={undefined}
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
        {!userServiceAccount && (
          <>
            <Grid size={4}>
              <AuditsRadar
                variant={undefined}
                startDate={undefined}
                endDate={undefined}
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
            <Grid size={8}>
              <AuditsList
                variant={undefined}
                startDate={undefined}
                endDate={undefined}
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
            <Grid size={4}>
              <AuditsHorizontalBars
                variant={undefined}
                startDate={undefined}
                endDate={undefined}
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
          </>
        )}
      </Grid>
    </>
  );
};

export default UserAnalytics;
