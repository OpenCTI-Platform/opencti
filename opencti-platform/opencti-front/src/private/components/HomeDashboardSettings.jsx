import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';

import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@filigran/design-system';
import React from 'react';
import { graphql } from 'react-relay';

import { useFormatter } from '../../components/i18n';
import { QueryRenderer } from '../../relay/environment';
import useAuth from '../../utils/hooks/useAuth';
import useGranted, { EXPLORE, KNOWLEDGE } from '../../utils/hooks/useGranted';
import Security from '../../utils/Security';
import ItemIcon from '../../components/ItemIcon';
import useApiMutation from '../../utils/hooks/useApiMutation';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
export const PLATFORM_DASHBOARD = 'cf093b57-713f-404b-a210-a1c5c8cb3791';

export const dashboardSettingsDashboardsQuery = graphql`
  query HomeDashboardSettingsDashboardsQuery(
    $count: Int!
    $orderBy: WorkspacesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    workspaces(
      first: $count
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const dashboardSettingsMutation = graphql`
  mutation HomeDashboardSettingsMutation($input: [EditInput]!) {
    meEdit(input: $input) {
      ...HomeDashboardMeFragment
    }
  }
`;

const HomeDashboardSettings = () => {
  const hasKnowledgeAccess = useGranted([KNOWLEDGE]);

  const { t_i18n } = useFormatter();
  const {
    me: {
      default_time_field: timeField,
      default_dashboard: dashboard,
      default_dashboards: dashboards,
    },
  } = useAuth();
  const [updateDashboard] = useApiMutation(dashboardSettingsMutation);
  const handleUpdate = (name, newValue) => {
    let value = newValue;
    if (value === 'automatic') {
      value = '';
    }
    updateDashboard({ variables: { input: [{ key: name, value }] } });
  };

  if (!hasKnowledgeAccess) {
    return null;
  }

  return (
    <Security
      needs={[EXPLORE]}
      placeholder={(
        <Select
          value={timeField === null ? '' : timeField}
          onValueChange={(value) => handleUpdate('default_time_field', value)
          }
        >
          <SelectLabel>{t_i18n('Date reference')}</SelectLabel>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="technical">{t_i18n('Technical date')}</SelectItem>
            <SelectItem value="functional">{t_i18n('Functional date')}</SelectItem>
          </SelectContent>
        </Select>
      )}
    >
      <QueryRenderer
        query={dashboardSettingsDashboardsQuery}
        variables={{
          count: 50,
          orderBy: 'name',
          orderMode: 'asc',
          filters: {
            mode: 'and',
            filters: [{ key: 'type', values: ['dashboard'] }],
            filterGroups: [],
          },
        }}
        render={({ props }) => {
          if (props) {
            const workspaces = props.workspaces.edges.filter(
              ({ node: { id } }) => !dashboards.some((d) => d.id === id),
            );
            return (
              <>
                <FormControl style={{ width: '100%' }}>
                  <InputLabel id="timeField">
                    {t_i18n('Date reference')}
                  </InputLabel>
                  <Select
                    value={timeField ?? 'technical'}
                    onValueChange={(value) => handleUpdate(
                      'default_time_field',
                      value,
                    )
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="technical">
                        {t_i18n('Technical date')}
                      </SelectItem>
                      <SelectItem value="functional">
                        {t_i18n('Functional date')}
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </FormControl>
                <FormControl style={{ width: '100%', marginTop: 20 }}>
                  <InputLabel id="timeField">
                    {t_i18n('Custom dashboard')}
                  </InputLabel>
                  <Select
                    value={dashboard?.id ?? 'automatic'}
                    onValueChange={(value) => handleUpdate('default_dashboard', value)}
                  >
                    <SelectTrigger aria-label={t_i18n('Custom dashboard')}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent aria-label={t_i18n('Custom dashboard')}>
                      <SelectItem value="automatic">
                        <em>{t_i18n('Default dashboard')}</em>
                      </SelectItem>
                      <SelectItem value={PLATFORM_DASHBOARD}>
                        <em>{t_i18n('Platform dashboard')}</em>
                      </SelectItem>
                      {dashboards.length > 0 && (
                        <SelectGroup>
                          <SelectLabel>
                            {t_i18n('Dashboards from your groups & organizations')}
                          </SelectLabel>
                          {dashboards.map(({ id, name }) => (
                            <SelectItem key={id} value={id}>
                              <ItemIcon type="Dashboard" />
                              <span>{name}</span>
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      )}
                      {workspaces?.length > 0 && (
                        <SelectGroup>
                          <SelectLabel>{t_i18n('Other custom dashboards')}</SelectLabel>
                          {workspaces.map(({ node }) => (
                            <SelectItem key={node.id} value={node.id}>
                              <ItemIcon type="Dashboard" />
                              <span>{node.name}</span>
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      )}
                    </SelectContent>
                  </Select>
                </FormControl>
              </>
            );
          }
          return <div />;
        }}
      />
    </Security>
  );
};

export default HomeDashboardSettings;
