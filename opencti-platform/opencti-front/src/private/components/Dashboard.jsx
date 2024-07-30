import { DescriptionOutlined, DiamondOutlined } from '@mui/icons-material';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { makeStyles } from '@mui/styles';
import { Biohazard, ShieldSearch } from 'mdi-material-ui';
import { assoc, head, last, map, pluck } from 'ramda';
import React, { Suspense } from 'react';
import { graphql, useFragment, usePreloadedQuery } from 'react-relay';
import DashboardSettings, { PLATFORM_DASHBOARD } from './DashboardSettings';
import StixRelationshipsDistributionList from './common/stix_relationships/StixRelationshipsDistributionList';
import StixRelationshipsPolarArea from './common/stix_relationships/StixRelationshipsPolarArea';
import StixCoreObjectsList from './common/stix_core_objects/StixCoreObjectsList';
import StixRelationshipsMultiAreaChart from './common/stix_relationships/StixRelationshipsMultiAreaChart';
import StixCoreObjectsNumber from './common/stix_core_objects/StixCoreObjectsNumber';
import { useFormatter } from '../../components/i18n';
import Loader, { LoaderVariant } from '../../components/Loader';
import useAuth, { UserContext } from '../../utils/hooks/useAuth';
import { EXPLORE, KNOWLEDGE } from '../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../utils/hooks/useLocalStorage';
import { computeLevel } from '../../utils/Number';
import Security from '../../utils/Security';
import { lastDayOfThePreviousMonth, monthsAgo, yearsAgo } from '../../utils/Time';
import LocationMiniMapTargets from './common/location/LocationMiniMapTargets';
import StixRelationshipsHorizontalBars from './common/stix_relationships/StixRelationshipsHorizontalBars';
import DashboardView from './workspaces/dashboards/Dashboard';
import useQueryLoading from '../../utils/hooks/useQueryLoading';
import useConnectedDocumentModifier from '../../utils/hooks/useConnectedDocumentModifier';
import WidgetLoader from '../../components/dashboard/WidgetLoader';

// region styles
// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  root: {
    marginRight: -20,
    paddingRight: 20,
    paddingBottom: 30,
  },
  card: {
    width: '100%',
    borderRadius: 4,
    position: 'relative',
  },
  paper: {
    margin: '10px 0 0 0',
    padding: 0,
    overflow: 'hidden',
  },
  title: {
    marginTop: 5,
    textTransform: 'uppercase',
    fontSize: 12,
    fontWeight: 500,
    color: theme.palette.text.secondary,
  },
  icon: {
    position: 'absolute',
    color: theme.palette.primary.main,
    top: 35,
    right: 20,
  },
}));
// endregion

// region inner components

// TargetedCountries
const dashboardStixCoreRelationshipsDistributionQuery = graphql`
  query DashboardStixCoreRelationshipsDistributionQuery(
    $field: String!
    $operation: StatsOperation!
    $relationship_type: [String]
    $isTo: Boolean
    $toRole: String
    $toTypes: [String]
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $limit: Int
  ) {
    stixCoreRelationshipsDistribution(
      field: $field
      operation: $operation
      relationship_type: $relationship_type
      isTo: $isTo
      toRole: $toRole
      toTypes: $toTypes
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      limit: $limit
    ) {
      label
      value
      entity {
        ... on BasicObject {
          entity_type
        }
        ... on BasicRelationship {
          entity_type
        }
        ... on StixObject {
          representative {
            main
          }
        }
        ... on StixRelationship {
          representative {
            main
          }
        }
        ... on Country {
          # nullable fields, so it will work even if the Country is Restricted
          x_opencti_aliases
          latitude
          longitude
        }
      }
    }
  }
`;
const TargetedCountriesComponent = ({ queryRef }) => {
  const data = usePreloadedQuery(
    dashboardStixCoreRelationshipsDistributionQuery,
    queryRef,
  );
  const values = pluck('value', data.stixCoreRelationshipsDistribution);
  const countries = map(
    (x) => assoc(
      'level',
      computeLevel(x.value, last(values), head(values) + 1),
      x.entity,
    ),
    data.stixCoreRelationshipsDistribution,
  );
  return (
    <LocationMiniMapTargets
      center={[48.8566969, 2.3514616]}
      countries={countries}
      zoom={2}
    />
  );
};
const TargetedCountries = ({ timeField }) => {
  const queryOptions = {
    field: 'internal_id',
    operation: 'count',
    relationship_type: 'targets',
    isTo: true,
    toRole: 'targets_to',
    toTypes: ['Country'],
    startDate: monthsAgo(3),
    dateAttribute: timeField === 'functional' ? 'start_time' : 'created_at',
    limit: 100,
  };
  const queryRef = useQueryLoading(
    dashboardStixCoreRelationshipsDistributionQuery,
    queryOptions,
  );
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<WidgetLoader />}>
          <TargetedCountriesComponent queryRef={queryRef} />
        </React.Suspense>
      )}
    </>
  );
};
// endregion

const DefaultDashboard = ({ timeField }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  return (
    <Security
      needs={[KNOWLEDGE]}
      placeholder={t_i18n(
        'You do not have any access to the knowledge of this OpenCTI instance.',
      )}
    >
      <Grid container={true} spacing={3}>
        <Grid item xs={3}>
          <Card
            classes={{ root: classes.card }}
            style={{ height: 110 }}
            variant="outlined"
          >
            <CardContent>
              <div className={classes.title}>{t_i18n('Intrusion Sets')}</div>
              <StixCoreObjectsNumber
                variant="inLine"
                withoutTitle={true}
                dataSelection={[{
                  filters: {
                    mode: 'and',
                    filters: [
                      {
                        key: 'entity_type',
                        values: ['Intrusion-Set'],
                      },
                    ],
                    filterGroups: [],
                  },
                  date_attribute: timeField === 'functional' ? 'start_time' : 'created_at',
                }]}
              />
              <div className={classes.icon}>
                <DiamondOutlined color="inherit" fontSize="large" />
              </div>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={3}>
          <Card
            classes={{ root: classes.card }}
            style={{ height: 110 }}
            variant="outlined"
          >
            <CardContent>
              <div className={classes.title}>{t_i18n('Malwares')}</div>
              <StixCoreObjectsNumber
                variant="inLine"
                withoutTitle={true}
                dataSelection={[{
                  filters: {
                    mode: 'and',
                    filters: [
                      {
                        key: 'entity_type',
                        values: ['Malware'],
                      },
                    ],
                    filterGroups: [],
                  },
                  date_attribute: timeField === 'functional' ? 'start_time' : 'created_at',
                }]}
              />
              <div className={classes.icon}>
                <Biohazard color="inherit" fontSize="large" />
              </div>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={3}>
          <Card
            classes={{ root: classes.card }}
            style={{ height: 110 }}
            variant="outlined"
          >
            <CardContent>
              <div className={classes.title}>{t_i18n('Reports')}</div>
              <StixCoreObjectsNumber
                variant="inLine"
                withoutTitle={true}
                dataSelection={[{
                  filters: {
                    mode: 'and',
                    filters: [
                      {
                        key: 'entity_type',
                        values: ['Report'],
                      },
                    ],
                    filterGroups: [],
                  },
                  date_attribute: timeField === 'functional' ? 'start_time' : 'created_at',
                }]}
              />
              <div className={classes.icon}>
                <DescriptionOutlined color="inherit" fontSize="large" />
              </div>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={3}>
          <Card
            classes={{ root: classes.card }}
            style={{ height: 110 }}
            variant="outlined"
          >
            <CardContent>
              <div className={classes.title}>{t_i18n('Indicators')}</div>
              <StixCoreObjectsNumber
                variant="inLine"
                withoutTitle={true}
                dataSelection={[{
                  filters: {
                    mode: 'and',
                    filters: [
                      {
                        key: 'entity_type',
                        values: ['Indicator'],
                      },
                    ],
                    filterGroups: [],
                  },
                  date_attribute: timeField === 'functional' ? 'created' : 'created_at',
                }]}
              />
              <div className={classes.icon}>
                <ShieldSearch color="inherit" fontSize="large" />
              </div>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={3}>
          <StixRelationshipsHorizontalBars
            title={t_i18n('Most active threats (3 last months)')}
            height={300}
            startDate={monthsAgo(3)}
            dataSelection={[{
              attribute: 'internal_id',
              isTo: false,
              filters: {
                mode: 'and',
                filters: [
                  {
                    key: 'fromTypes',
                    mode: 'or',
                    values: ['Threat-Actor', 'Intrusion-Set', 'Campaign'],
                  },
                  {
                    key: 'entity_type',
                    values: ['stix-core-relationship'],
                  },
                ],
                filterGroups: [],
              },
              date_attribute: timeField === 'functional' ? 'start_time' : 'created_at',
            }]}
          />
        </Grid>
        <Grid item xs={3}>
          <StixRelationshipsHorizontalBars
            title={t_i18n('Most targeted victims (3 last months)')}
            height={300}
            startDate={monthsAgo(3)}
            dataSelection={[{
              attribute: 'internal_id',
              isTo: true,
              filters: {
                mode: 'and',
                filters: [
                  {
                    key: 'toTypes',
                    mode: 'or',
                    values: ['Identity', 'Location', 'Event'],
                  },
                  {
                    key: 'relationship_type',
                    values: ['targets'],
                  },
                ],
                filterGroups: [],
              },
              date_attribute: timeField === 'functional' ? 'start_time' : 'created_at',
            }]}
          />
        </Grid>
        <Grid item xs={6}>
          <StixRelationshipsMultiAreaChart
            title={t_i18n('Relationships created')}
            height={300}
            startDate={yearsAgo(1)}
            endDate={lastDayOfThePreviousMonth()}
            parameters={{
              interval: 'month',
            }}
            dataSelection={[{
              attribute: 'internal_id',
              isTo: true,
              filters: {
                mode: 'and',
                filters: [
                  {
                    key: 'entity_type',
                    values: ['stix-core-relationship'],
                  },
                ],
                filterGroups: [],
              },
              date_attribute: timeField === 'functional' ? 'start_time' : 'created_at',
            }]}
          />
        </Grid>
        <Grid item xs={3} style={{ marginTop: 25 }}>
          <StixRelationshipsPolarArea
            title={t_i18n('Most active malware (3 last months)')}
            height={400}
            startDate={monthsAgo(3)}
            dataSelection={[{
              attribute: 'internal_id',
              isTo: false,
              filters: {
                mode: 'and',
                filters: [
                  {
                    key: 'fromTypes',
                    values: ['Malware'],
                  },
                  {
                    key: 'entity_type',
                    values: ['uses'],
                  },
                ],
                filterGroups: [],
              },
              date_attribute: timeField === 'functional' ? 'start_time' : 'created_at',
            }]}
          />
        </Grid>
        <Grid item xs={3} style={{ marginTop: 25 }}>
          <StixRelationshipsDistributionList
            overflow="hidden"
            title={t_i18n('Most active vulnerabilities (3 last months)')}
            height={400}
            startDate={monthsAgo(3)}
            dataSelection={[{
              attribute: 'internal_id',
              isTo: true,
              number: 8,
              filters: {
                mode: 'and',
                filters: [
                  {
                    key: 'entity_type',
                    values: ['targets'],
                  },
                  {
                    key: 'toTypes',
                    values: ['Vulnerability'],
                  },
                ],
                filterGroups: [],
              },
              date_attribute: timeField === 'functional' ? 'start_time' : 'created_at',
            }]}
          />
        </Grid>
        <Grid item xs={6} style={{ marginTop: 25 }}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Targeted countries (3 last months)')}
          </Typography>
          <Paper
            classes={{ root: classes.paper }}
            variant="outlined"
            style={{ height: 400 }}
          >
            <Suspense
              fallback={
                <LocationMiniMapTargets
                  center={[48.8566969, 2.3514616]}
                  zoom={2}
                />
              }
            >
              <TargetedCountries timeField={timeField} />
            </Suspense>
          </Paper>
        </Grid>
        <Grid item xs={8}>
          <StixCoreObjectsList
            title={t_i18n('Latest reports')}
            height={410}
            dataSelection={[{
              filters: {
                mode: 'and',
                filters: [
                  {
                    key: 'entity_type',
                    values: ['Report'],
                  },
                ],
                filterGroups: [],
              },
              date_attribute: timeField === 'functional' ? 'start_time' : 'created_at',
            }]}
          />
        </Grid>
        <Grid item xs={4}>
          <StixRelationshipsHorizontalBars
            title={t_i18n('Most active labels (3 last months)')}
            height={410}
            startDate={monthsAgo(3)}
            parameters={{ number: 15 }}
            dataSelection={[{
              attribute: 'internal_id',
              isTo: true,
              filters: {
                mode: 'and',
                filters: [
                  {
                    key: 'toTypes',
                    mode: 'or',
                    values: ['Label'],
                  },
                ],
                filterGroups: [],
              },
              date_attribute: timeField === 'functional' ? 'start_time' : 'created_at',
            }]}
          />
        </Grid>
      </Grid>
    </Security>
  );
};

const dashboardCustomDashboardQuery = graphql`
  query DashboardCustomDashboardQuery($id: String!) {
    workspace(id: $id) {
      id
      name
      ...Dashboard_workspace
    }
  }
`;
const WorkspaceDashboardComponent = ({ queryRef, timeField }) => {
  const data = usePreloadedQuery(dashboardCustomDashboardQuery, queryRef);
  if (data.workspace) {
    return (
      <DashboardView
        workspace={data.workspace}
        noToolbar={true}
        timeField={timeField}
      />
    );
  }
  return <DefaultDashboard timeField={timeField} />;
};
const WorkspaceDashboard = ({ dashboard, timeField }) => {
  const queryRef = useQueryLoading(dashboardCustomDashboardQuery, {
    id: dashboard,
  });
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <WorkspaceDashboardComponent
            timeField={timeField}
            queryRef={queryRef}
          />
        </React.Suspense>
      )}
    </>
  );
};
const CustomDashboard = ({ dashboard, timeField }) => {
  const { t_i18n } = useFormatter();
  return (
    <Security
      needs={[EXPLORE]}
      placeholder={t_i18n(
        'You do not have any access to the explore part of this OpenCTI instance.',
      )}
    >
      <Suspense fallback={<Loader />}>
        <WorkspaceDashboard dashboard={dashboard} timeField={timeField} />
      </Suspense>
    </Security>
  );
};

const dashboardQuery = graphql`
  query DashboardQuery {
    me {
      ...DashboardMeFragment
    }
  }
`;

const dashboardMeFragment = graphql`
  fragment DashboardMeFragment on MeUser {
    id
    default_dashboard {
      id
    }
    default_time_field
  }
`;

const LOCAL_STORAGE_KEY = 'dashboard';

const DashboardComponent = ({ queryRef }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { me: currentMe, ...context } = useAuth();
  const data = usePreloadedQuery(dashboardQuery, queryRef);
  const me = useFragment(dashboardMeFragment, data.me);
  const { default_dashboards: dashboards } = currentMe;
  const { default_time_field, default_dashboard } = me;
  const { viewStorage: localTimeFieldPreferences } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    {},
  );
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Dashboard'));
  const { dashboard } = localTimeFieldPreferences;
  let defaultDashboard = default_dashboard?.id;
  if (!defaultDashboard) {
    defaultDashboard = dashboards[0]?.id ?? PLATFORM_DASHBOARD;
  } else if (dashboard && dashboard !== 'default') {
    // Handle old conf
    defaultDashboard = dashboard;
  }

  return (
    <UserContext.Provider value={{ me: { ...currentMe, ...me }, ...context }}>
      <div className={classes.root} data-testid="dashboard-page">
        {defaultDashboard !== PLATFORM_DASHBOARD ? (
          <CustomDashboard
            dashboard={defaultDashboard}
            timeField={default_time_field}
          />
        ) : (
          <DefaultDashboard timeField={default_time_field} />
        )}
      </div>
      <DashboardSettings />
    </UserContext.Provider>
  );
};

const Dashboard = () => {
  const queryRef = useQueryLoading(dashboardQuery, {});
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<div />}>
          <DashboardComponent queryRef={queryRef} />
        </React.Suspense>
      )}
    </>
  );
};

export default Dashboard;
