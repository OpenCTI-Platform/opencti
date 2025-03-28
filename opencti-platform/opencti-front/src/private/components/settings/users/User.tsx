import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import { DeleteForeverOutlined, DeleteOutlined, RefreshOutlined, Visibility, VisibilityOff } from '@mui/icons-material';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import { Link } from 'react-router-dom';
import { useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import { ApexOptions } from 'apexcharts';
import { SimplePaletteColorOptions } from '@mui/material/styles/createPalette';
import UserConfidenceLevel from '@components/settings/users/UserConfidenceLevel';
import { UserUserRenewTokenMutation } from '@components/settings/users/__generated__/UserUserRenewTokenMutation.graphql';
import Tooltip from '@mui/material/Tooltip';
import { ListItemButton } from '@mui/material';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { useFormatter } from '../../../../components/i18n';
import { handleError, QueryRenderer } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { now, timestamp, yearsAgo } from '../../../../utils/Time';
import UserHistory from './UserHistory';
import { areaChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';
import Transition from '../../../../components/Transition';
import { User_user$key } from './__generated__/User_user.graphql';
import Chart from '../../common/charts/Chart';
import { UserSessionKillMutation } from './__generated__/UserSessionKillMutation.graphql';
import { UserUserSessionsKillMutation } from './__generated__/UserUserSessionsKillMutation.graphql';
import Triggers from '../common/Triggers';
import { UserAuditsTimeSeriesQuery$data } from './__generated__/UserAuditsTimeSeriesQuery.graphql';
import { UserOtpDeactivationMutation } from './__generated__/UserOtpDeactivationMutation.graphql';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import ItemIcon from '../../../../components/ItemIcon';
import HiddenTypesChipList from '../hidden_types/HiddenTypesChipList';
import ItemAccountStatus from '../../../../components/ItemAccountStatus';
import useGranted, { BYPASS, KNOWLEDGE, SETTINGS_SECURITYACTIVITY, SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import useAuth from '../../../../utils/hooks/useAuth';
import type { Theme } from '../../../../components/Theme';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import ItemCopy from '../../../../components/ItemCopy';
import { maskString } from '../../../../utils/String';

const startDate = yearsAgo(1);
const endDate = now();

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  floatingButton: {
    float: 'left',
    margin: '-8px 0 0 5px',
  },
  gridContainer: {
    marginBottom: 50,
  },
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
}));

export const userSessionKillMutation = graphql`
  mutation UserSessionKillMutation($id: ID!) {
    sessionKill(id: $id)
  }
`;

export const userUserSessionsKillMutation = graphql`
  mutation UserUserSessionsKillMutation($id: ID!) {
    userSessionsKill(id: $id)
  }
`;

export const userUserRenewTokenMutation = graphql`
    mutation UserUserRenewTokenMutation($id: ID!) {
        userEdit(id: $id) {
            tokenRenew {
                id
                api_token
            }
        }
    }
`;

export const userOtpDeactivationMutation = graphql`
  mutation UserOtpDeactivationMutation($id: ID!) {
    otpUserDeactivation(id: $id) {
      ...ProfileOverview_me
    }
  }
`;

const UserAuditsTimeSeriesQuery = graphql`
  query UserAuditsTimeSeriesQuery(
    $types: [String!]
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
    $filters: FilterGroup
  ) {
    auditsTimeSeries(
      types: $types
      field: $field
      filters: $filters
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
    ) {
      date
      value
    }
  }
`;

const UserFragment = graphql`
  fragment User_user on User
  @argumentDefinitions(
    groupsOrderBy: { type: "GroupsOrdering", defaultValue: name }
    groupsOrderMode: { type: "OrderingMode", defaultValue: asc }
    organizationsOrderBy: { type: "OrganizationsOrdering", defaultValue: name }
    organizationsOrderMode: { type: "OrderingMode", defaultValue: asc }
    organizationsCount: { type: "Int", defaultValue: 500 }
    rolesOrderBy: { type: "RolesOrdering", defaultValue: name }
    rolesOrderMode: { type: "OrderingMode", defaultValue: asc }
  ) {
    id
    name
    description
    external
    user_email
    firstname
    lastname
    account_status
    account_lock_after_date
    language
    api_token
    otp_activated
    roles(orderBy: $rolesOrderBy, orderMode: $rolesOrderMode) {
      id
      name
      description
    }
    capabilities {
      id
      name
    }
    groups(orderBy: $groupsOrderBy, orderMode: $groupsOrderMode) {
      edges {
        node {
          id
          name
          description
        }
      }
    }
    default_hidden_types
    user_confidence_level {
      max_confidence
      overrides {
        max_confidence
        entity_type
      }
    }
    effective_confidence_level {
      max_confidence
      overrides {
        max_confidence
        entity_type
        source {
          type
          object {
            ... on User { entity_type id name }
            ... on Group { entity_type id name }
          }
        }
      }
      source {
        type
        object {
          ... on User { entity_type id name }
          ... on Group { entity_type id name }
        }
      }
    }
    objectOrganization(
      first: $organizationsCount
      orderBy: $organizationsOrderBy
      orderMode: $organizationsOrderMode
    ) {
      edges {
        node {
          id
          name
          authorized_authorities
        }
      }
    }
    sessions {
      id
      created
      ttl
    }
  }
`;

type Session = {
  id: string;
  created?: string;
  ttl?: number;
};

interface UserProps {
  data: User_user$key;
  refetch: () => void;
}

const User: FunctionComponent<UserProps> = ({ data, refetch }) => {
  const classes = useStyles();
  const { t_i18n, nsdt, fsd, fldt } = useFormatter();
  const { me } = useAuth();
  const theme = useTheme<Theme>();
  const [showToken, setShowToken] = useState<boolean>(false);
  const [displayKillSession, setDisplayKillSession] = useState<boolean>(false);
  const [displayKillSessions, setDisplayKillSessions] = useState<boolean>(false);
  const [displayRenewToken, setDisplayRenewToken] = useState<boolean>(false);
  const [killing, setKilling] = useState<boolean>(false);
  const [sessionToKill, setSessionToKill] = useState<string | null>(null);
  const user = useFragment(UserFragment, data);
  const isEnterpriseEdition = useEnterpriseEdition();
  const isGrantedToAudit = useGranted([SETTINGS_SECURITYACTIVITY]);
  const isGrantedToKnowledge = useGranted([KNOWLEDGE]);
  const [commitUserSessionKill] = useApiMutation<UserSessionKillMutation>(
    userSessionKillMutation,
  );
  const [commitUserUserSessionsKill] = useApiMutation<UserUserSessionsKillMutation>(userUserSessionsKillMutation);
  const [commitUserUserRenewToken] = useApiMutation<UserUserRenewTokenMutation>(userUserRenewTokenMutation);
  const [commitUserOtpDeactivation] = useApiMutation<UserOtpDeactivationMutation>(
    userOtpDeactivationMutation,
  );
  const userCapabilities = (me.capabilities ?? []).map((c) => c.name);
  const userHasSettingsCapability = userCapabilities.includes(SETTINGS_SETACCESSES) || userCapabilities.includes(BYPASS);
  const handleOpenKillSession = (sessionId: string) => {
    setDisplayKillSession(true);
    setSessionToKill(sessionId);
  };
  const handleCloseKillSession = () => {
    setDisplayKillSession(false);
    setSessionToKill(null);
  };
  const submitKillSession = () => {
    if (sessionToKill) {
      setKilling(true);
      commitUserSessionKill({
        variables: {
          id: sessionToKill,
        },
        onError: (error: Error) => {
          handleError(error);
          setKilling(false);
        },
        onCompleted: () => {
          setKilling(false);
          handleCloseKillSession();
          refetch();
        },
      });
    }
  };
  const handleOpenKillSessions = () => {
    setDisplayKillSessions(true);
  };
  const handleCloseKillSessions = () => {
    setDisplayKillSessions(false);
  };
  const submitKillSessions = () => {
    setKilling(true);
    commitUserUserSessionsKill({
      variables: {
        id: user.id,
      },
      onError: (error: Error) => {
        handleError(error);
        setKilling(false);
      },
      onCompleted: () => {
        setKilling(false);
        handleCloseKillSessions();
        refetch();
      },
    });
  };

  const handleOpenRenewToken = () => {
    setDisplayRenewToken(true);
  };
  const handleCloseRenewToken = () => {
    setDisplayRenewToken(false);
  };
  const submitRenewToken = () => {
    commitUserUserRenewToken({
      variables: {
        id: user.id,
      },
      onError: (error: Error) => {
        handleError(error);
      },
      onCompleted: () => {
        handleCloseRenewToken();
        refetch();
      },
    });
  };

  const otpUserDeactivation = () => {
    commitUserOtpDeactivation({
      variables: {
        id: user.id,
      },
      onError: (error: Error) => {
        handleError(error);
      },
    });
  };
  const orderedSessions: Session[] = (user.sessions ?? [])
    .map((s) => ({
      created: s?.created ?? '',
      id: s?.id ?? '',
      ttl: s?.ttl ?? 0,
    }))
    .sort(
      (a: Session, b: Session) => timestamp(a?.created) - timestamp(b?.created),
    );
  const accountExpireDate = fldt(user.account_lock_after_date);
  let historyTypes = ['History'];
  if (isGrantedToAudit && !isGrantedToKnowledge) {
    historyTypes = ['Activity'];
  } else if (isGrantedToAudit && isGrantedToKnowledge) {
    historyTypes = ['History', 'Activity'];
  }

  return (
    <>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item xs={6}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Basic information')}
          </Typography>
          <Paper classes={{ root: classes.paper }} className="paper-for-grid" variant="outlined">
            <Grid container={true} spacing={3}>
              <Grid item xs={8}>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ marginBottom: user.otp_activated ? 7 : 5 }}
                >
                  {t_i18n('Email address')}
                </Typography>
                <pre style={{ margin: 0 }}>{user.user_email}</pre>
              </Grid>
              <Grid item xs={4}>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t_i18n('2FA state')}
                </Typography>
                {user.otp_activated && (
                  <IconButton
                    classes={{ root: classes.floatingButton }}
                    color="primary"
                    onClick={otpUserDeactivation}
                    aria-label="Delete all"
                    size="small"
                  >
                    <DeleteForeverOutlined fontSize="small" />
                  </IconButton>
                )}
                <div className="clearfix" />
                <pre style={{ margin: 0 }}>
                  {user.otp_activated ? t_i18n('Enabled') : t_i18n('Disabled')}
                </pre>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
                  {t_i18n('Token')}
                </Typography>
                <Security needs={[SETTINGS_SETACCESSES]}>
                  <Tooltip title={t_i18n('Revoke token')}>
                    <IconButton
                      color='primary'
                      aria-label={t_i18n('Revoke token')}
                      onClick={handleOpenRenewToken}
                      classes={{ root: classes.floatingButton }}
                      size='small'
                    >
                      <RefreshOutlined fontSize='small'/>
                    </IconButton>
                  </Tooltip>
                </Security>
                <div className="clearfix"/>
                <pre
                  style={{
                    margin: 0,
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    width: '100%',
                    padding: `${theme.spacing(1)}`,
                  }}
                >
                  <span style={{ flexGrow: 1 }}>
                    <ItemCopy
                      content={showToken ? user.api_token : maskString(user.api_token)}
                      value={user.api_token}
                    />
                  </span>
                  <IconButton
                    style={{
                      cursor: 'pointer',
                      color: theme.palette.primary.main,
                      padding: `0 ${theme.spacing(1)}`,
                    }}
                    disableRipple
                    onClick={() => setShowToken((value) => !value)}
                    aria-label={showToken ? t_i18n('Hide') : t_i18n('Show')}
                  >
                    {showToken ? <VisibilityOff/> : <Visibility/>}
                  </IconButton>
                </pre>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Firstname')}
                </Typography>
                {user.firstname || '-'}
              </Grid>
              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Lastname')}
                </Typography>
                {user.lastname || '-'}
              </Grid>
              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Account status')}
                </Typography>
                <ItemAccountStatus
                  account_status={user.account_status}
                  label={t_i18n(user.account_status || 'Unknown')}
                  variant="outlined"
                />
              </Grid>
              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Account expiration date')}
                </Typography>
                {accountExpireDate || '-'}
              </Grid>
            </Grid>
          </Paper>
        </Grid>
        <Grid item xs={6}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Permissions')}
          </Typography>
          <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
            <Grid container={true} spacing={3}>
              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Roles')}
                </Typography>
                <FieldOrEmpty source={user.roles ?? []}>
                  <List>
                    {(user.roles ?? []).map((role) => (userHasSettingsCapability ? (
                      <ListItemButton
                        key={role?.id}
                        dense={true}
                        divider={true}
                        component={Link}
                        to={`/dashboard/settings/accesses/roles/${role?.id}`}
                      >
                        <ListItemIcon>
                          <ItemIcon type="Role" />
                        </ListItemIcon>
                        <ListItemText primary={role?.name} />
                      </ListItemButton>
                    ) : (
                      <ListItem key={role?.id} dense={true} divider={true}>
                        <ListItemIcon>
                          <ItemIcon type="Role" />
                        </ListItemIcon>
                        <ListItemText primary={role?.name} />
                      </ListItem>
                    )))}
                  </List>
                </FieldOrEmpty>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Groups')}
                </Typography>
                <FieldOrEmpty source={user.groups?.edges}>
                  <List>
                    {(user.groups?.edges ?? []).map((groupEdge) => (userHasSettingsCapability ? (
                      <ListItemButton
                        key={groupEdge?.node.id}
                        dense={true}
                        divider={true}
                        component={Link}
                        to={`/dashboard/settings/accesses/groups/${groupEdge?.node.id}`}
                      >
                        <ListItemIcon>
                          <ItemIcon type="Group" />
                        </ListItemIcon>
                        <ListItemText primary={groupEdge?.node.name} />
                      </ListItemButton>
                    ) : (
                      <ListItem
                        key={groupEdge?.node.id}
                        dense={true}
                        divider={true}
                      >
                        <ListItemIcon>
                          <ItemIcon type="Group" />
                        </ListItemIcon>
                        <ListItemText primary={groupEdge?.node.name} />
                      </ListItem>
                    )))}
                  </List>
                </FieldOrEmpty>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Organizations')}
                </Typography>
                <FieldOrEmpty source={user.objectOrganization?.edges}>
                  <List>
                    {user.objectOrganization?.edges.map((organizationEdge) => (
                      <ListItemButton
                        key={organizationEdge.node.id}
                        dense={true}
                        divider={true}
                        component={Link}
                        to={`/dashboard/settings/accesses/organizations/${organizationEdge.node.id}`}
                      >
                        <ListItemIcon>
                          <ItemIcon
                            type="Organization"
                            color={
                              (
                                organizationEdge.node.authorized_authorities
                                ?? []
                              ).includes(user.id)
                                ? (
                                  theme.palette
                                    .warning as SimplePaletteColorOptions
                                ).main
                                : theme.palette.primary.main
                            }
                          />
                        </ListItemIcon>
                        <ListItemText primary={organizationEdge.node.name} />
                      </ListItemButton>
                    ))}
                  </List>
                </FieldOrEmpty>
              </Grid>
              <Grid item xs={6}>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t_i18n('Sessions')}
                </Typography>
                <Security needs={[SETTINGS_SETACCESSES]}>
                  <Tooltip title={t_i18n('Kill all sessions')}>
                    <IconButton
                      color="primary"
                      aria-label={t_i18n('Delete all')}
                      onClick={handleOpenKillSessions}
                      classes={{ root: classes.floatingButton }}
                      size="small"
                    >
                      <DeleteForeverOutlined fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </Security>
                <div className="clearfix" />
                <FieldOrEmpty source={orderedSessions}>
                  <List style={{ marginTop: -2, width: '100%', maxHeight: 400, overflowY: 'auto' }}>
                    {orderedSessions
                      && orderedSessions.map((session: Session) => (
                        <ListItem
                          key={session.id}
                          dense={true}
                          divider={true}
                          secondaryAction={
                            <IconButton
                              aria-label="Kill"
                              onClick={() => handleOpenKillSession(session.id)}
                              size="small"
                            >
                              <DeleteOutlined fontSize="small" />
                            </IconButton>
                          }
                        >
                          <ListItemIcon>
                            <ItemIcon type="Session" />
                          </ListItemIcon>
                          <ListItemText
                            primary={
                              <>
                                <div style={{ float: 'left', width: '50%' }}>
                                  {nsdt(session.created)}
                                </div>
                                <div style={{ float: 'left', width: '20%' }}>
                                  {session.ttl
                                    ? Math.round(session.ttl / 60)
                                    : 0}{' '}
                                  {t_i18n('minutes')}
                                </div>
                              </>
                            }
                          />
                        </ListItem>
                      ))}
                  </List>
                </FieldOrEmpty>
              </Grid>
              <Grid item xs={6}>
                <HiddenTypesChipList
                  hiddenTypes={user.default_hidden_types ?? []}
                />
              </Grid>
              <Grid item xs={6}>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t_i18n('Max Confidence Level')}
                </Typography>
                <div className="clearfix"/>
                <UserConfidenceLevel user={user} />
              </Grid>
            </Grid>
          </Paper>
        </Grid>
        <Triggers recipientId={user.id} filterKey="authorized_members.id" />
        <Grid item xs={6} style={{ marginTop: 10 }}>
          <Typography variant="h4" gutterBottom={true} style={{ paddingBottom: '22px' }}>
            {t_i18n('Operations')}
          </Typography>
          <Paper
            classes={{ root: classes.paper }}
            variant="outlined"
            style={{ minHeight: 500 }}
            className={'paper-for-grid'}
          >
            {!isEnterpriseEdition ? (
              <div style={{ display: 'table', height: '100%', width: '100%' }}>
                <span
                  style={{
                    display: 'table-cell',
                    verticalAlign: 'middle',
                    textAlign: 'center',
                  }}
                >
                  {t_i18n(
                    'This feature is only available in OpenCTI Enterprise Edition.',
                  )}
                </span>
              </div>
            ) : (
              <QueryRenderer
                query={UserAuditsTimeSeriesQuery}
                variables={{
                  types: historyTypes,
                  field: 'timestamp',
                  operation: 'count',
                  startDate,
                  endDate,
                  interval: 'month',
                  filters: {
                    mode: 'and',
                    filters: [
                      { key: ['user_id'], values: [user.id], operator: 'wildcard', mode: 'or' },
                    ],
                    filterGroups: [],
                  },
                }}
                render={({
                  props,
                }: {
                  props: UserAuditsTimeSeriesQuery$data;
                }) => {
                  if (props && props.auditsTimeSeries) {
                    const chartData = props.auditsTimeSeries.map((entry) => ({
                      x: new Date(entry?.date),
                      y: entry?.value,
                    }));
                    return (
                      <Chart
                        options={
                          areaChartOptions(
                            theme,
                            true,
                            fsd,
                            simpleNumberFormat,
                            undefined,
                          ) as ApexOptions
                        }
                        series={[
                          {
                            name: t_i18n('Number of operations'),
                            data: chartData,
                          },
                        ]}
                        type="area"
                        width="100%"
                        height="100%"
                      />
                    );
                  }
                  return <Loader variant={LoaderVariant.inElement} />;
                }}
              />
            )}
          </Paper>
        </Grid>
        <Grid item xs={6} style={{ marginTop: 10 }}>
          {isGrantedToAudit ? (
            <UserHistory userId={user.id} />
          ) : (
            <>
              <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
                {t_i18n('History')}
              </Typography>
              <div style={{ display: 'table', height: '100%', width: '100%' }}>
                <Paper
                  classes={{ root: classes.paper }}
                  variant="outlined"
                  className={'paper-for-grid'}
                >
                  <span
                    style={{
                      display: 'flex',
                      justifyContent: 'center',
                      alignItems: 'center',
                      height: '100%',
                    }}
                  >
                    {t_i18n('You are not authorized to see this data.')}
                  </span>
                </Paper>
              </div>
            </>
          )}
        </Grid>
      </Grid>
      <Dialog
        open={displayKillSession}
        slotProps={{ paper: { elevation: 1 } }}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCloseKillSession}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to kill this session?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseKillSession} disabled={killing}>
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitKillSession}
            color="secondary"
            disabled={killing}
          >
            {t_i18n('Kill')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={displayKillSessions}
        slotProps={{ paper: { elevation: 1 } }}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCloseKillSessions}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to kill all the sessions of this user?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseKillSessions} disabled={killing}>
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitKillSessions}
            color="secondary"
            disabled={killing}
          >
            {t_i18n('Kill all')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={displayRenewToken}
        slotProps={{ paper: { elevation: 1 } }}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCloseRenewToken}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to revoke this user token ? Once the token is revoked all access are forbidden, please verify that the token is not used by connectors or other API calls before revoking.')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseRenewToken}>
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitRenewToken}
            color="secondary"
          >
            {t_i18n('Revoke')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default User;
