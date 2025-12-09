import { WarningOutlined } from '@mui/icons-material';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { InformationOutline } from 'mdi-material-ui';
import * as R from 'ramda';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router-dom';
import GroupConfidenceLevel from '@components/settings/groups/GroupConfidenceLevel';
import { uniq } from 'ramda';
import { ListItemButton } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import { truncate } from '../../../../utils/String';
import Triggers from '../common/Triggers';
import GroupUsers from '../users/GroupUsers';
import { Group_group$key } from './__generated__/Group_group.graphql';
import ItemIcon from '../../../../components/ItemIcon';
import GroupHiddenTypesChipList from './GroupHiddenTypesChipList';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { checkIsMarkingAllowed } from '../../../../utils/markings/markingsFiltering';
import type { Theme } from '../../../../components/Theme';
import MarkingIcon from '../../../../utils/MarkingIcon';
import Card from '../../../../components/common/card/Card';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
  gridContainer: {
    marginBottom: 20,
  },
}));

const groupFragment = graphql`
  fragment Group_group on Group
  @argumentDefinitions(
    rolesOrderBy: { type: "RolesOrdering", defaultValue: name }
    rolesOrderMode: { type: "OrderingMode", defaultValue: asc }
  ) {
    id
    standard_id
    entity_type
    name
    default_assignation
    auto_new_marking
    restrict_delete
    no_creators
    group_confidence_level {
      max_confidence
      overrides {
        max_confidence
        entity_type
      }
    }
    description
    default_dashboard {
      id
      name
      authorizedMembers {
        id  
        member_id
      }
    }
    roles(orderBy: $rolesOrderBy, orderMode: $rolesOrderMode) {
      edges {
        node {
          id
          name
          description
        }
      }
    }
    allowed_marking {
      id
      definition
      definition_type
      x_opencti_color
      x_opencti_order
    }
    not_shareable_marking_types
    max_shareable_marking {
      id
      definition
      definition_type
      x_opencti_color
      x_opencti_order
    }
    default_marking {
      entity_type
      values {
        id
        definition
        x_opencti_color
        x_opencti_order
      }
    }
    ...GroupHiddenTypesChipList_group
  }
`;
const Group = ({ groupData }: { groupData: Group_group$key }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const group = useFragment<Group_group$key>(groupFragment, groupData);

  const markingsSort = R.sortWith([
    R.ascend(R.propOr('TLP', 'definition_type')),
    R.descend(R.propOr(0, 'x_opencti_order')),
  ]);
  const allowedMarkings = markingsSort(group.allowed_marking ?? []);
  const markingTypes = uniq(allowedMarkings.map((marking) => marking.definition_type)).filter((type) => !!type) as string[];
  const maxShareableMarkings = markingsSort(group.max_shareable_marking ?? []);
  const maxShareableMarkingsByType = new Map(markingTypes.map((type) => {
    const sortedMaxMarkingsOfType = maxShareableMarkings.filter((m) => m.definition_type === type)
      .sort((a, b) => b.x_opencti_order - a.x_opencti_order);
    return [type, sortedMaxMarkingsOfType.length > 0 ? sortedMaxMarkingsOfType[0] : undefined];
  }));
  // Handle only GLOBAL entity type for now
  const globalDefaultMarkings = markingsSort(
    (group.default_marking ?? []).find((d) => d.entity_type === 'GLOBAL')
      ?.values ?? [],
  );
  const canAccessDashboard = (
    group.default_dashboard?.authorizedMembers || []
  ).some(({ member_id }) => {
    return member_id === 'ALL' || member_id === group.id;
  });

  return (
    <div className={classes.container} data-testid="group-details-page">
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item xs={6}>
          <Card title={t_i18n('Basic information')}>
            <Grid container={true} spacing={3}>
              <Grid item xs={12}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Description')}
                </Typography>
                <ExpandableMarkdown
                  source={group.description}
                  limit={400}
                />
              </Grid>
              <Grid item xs={12}>
                <GroupHiddenTypesChipList groupData={group} />
              </Grid>
              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Auto new markings')}
                </Typography>
                <ItemBoolean
                  status={group.auto_new_marking ?? false}
                  label={group.auto_new_marking ? t_i18n('Yes') : t_i18n('No')}
                />
              </Grid>
              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Default membership')}
                </Typography>
                <ItemBoolean
                  status={group.default_assignation ?? false}
                  label={group.default_assignation ? t_i18n('Yes') : t_i18n('No')}
                />
              </Grid>
            </Grid>
          </Card>
        </Grid>
        <Grid item xs={6}>
          <Card title={t_i18n('Permissions')}>
            <Grid container={true} spacing={3}>
              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Roles')}
                </Typography>
                <List>
                  {group.roles?.edges?.map(({ node: role }) => (
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
                  ))}
                </List>
              </Grid>
              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Default dashboard')}
                </Typography>
                <FieldOrEmpty source={group.default_dashboard}>
                  <List>
                    <ListItem
                      dense={true}
                      divider={true}
                      secondaryAction={!canAccessDashboard && (
                        <Tooltip
                          title={t_i18n(
                            'You need to authorize this group to access this dashboard in the permissions of the workspace.',
                          )}
                        >
                          <WarningOutlined color="warning" />
                        </Tooltip>
                      )}
                    >
                      <ListItemButton
                        component={Link}
                        to={`/dashboard/workspaces/dashboards/${group.default_dashboard?.id}`}
                      >
                        <ListItemIcon>
                          <ItemIcon type="Dashboard" />
                        </ListItemIcon>
                        <ListItemText
                          primary={truncate(group.default_dashboard?.name, 40)}
                        />
                      </ListItemButton>
                    </ListItem>
                  </List>
                </FieldOrEmpty>
              </Grid>
              <Grid item xs={12}>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ float: 'left' }}
                >
                  {t_i18n('Max Confidence Level')}
                </Typography>
                <div className="clearfix" />
                <GroupConfidenceLevel
                  confidenceLevel={group.group_confidence_level}
                />
              </Grid>
              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('No creators accumulation')}
                </Typography>
                <ItemBoolean
                  status={group.no_creators ?? false}
                  label={group.no_creators ? t_i18n('Yes') : t_i18n('No')}
                />
              </Grid>
              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Restrict delete to created entities')}
                </Typography>
                <ItemBoolean
                  status={group.restrict_delete ?? false}
                  label={group.restrict_delete ? t_i18n('Yes') : t_i18n('No')}
                />
              </Grid>
            </Grid>
          </Card>
        </Grid>
        <Grid item xs={12}>
          <Card title={t_i18n('Markings')}>
            <Grid container={true} spacing={3}>
              <Grid item xs={4}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Default markings')}
                  <Tooltip
                    title={t_i18n(
                      'You can enable/disable default values for marking in the customization of each entity type.',
                    )}
                  >
                    <InformationOutline
                      fontSize="small"
                      color="primary"
                      style={{ margin: '0 0 -5px 10px' }}
                    />
                  </Tooltip>
                </Typography>
                <FieldOrEmpty source={globalDefaultMarkings}>
                  <List style={{ marginTop: -3 }}>
                    {globalDefaultMarkings.map((marking) => (
                      <ListItem
                        key={marking?.id}
                        dense={true}
                        divider={true}

                      >
                        <ListItemIcon>
                          <MarkingIcon theme={theme} color={marking?.x_opencti_color} />
                        </ListItemIcon>
                        <ListItemText
                          primary={truncate(marking?.definition, 40)}
                        />
                      </ListItem>
                    ))}
                  </List>
                </FieldOrEmpty>
              </Grid>
              <Grid item xs={4}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Allowed markings')}
                </Typography>
                <FieldOrEmpty source={allowedMarkings}>
                  <List>
                    {allowedMarkings.map((marking) => (
                      <ListItem
                        key={marking?.id}
                        dense={true}
                        divider={true}

                      >
                        <ListItemIcon>
                          <MarkingIcon theme={theme} color={marking?.x_opencti_color} />
                        </ListItemIcon>
                        <ListItemText
                          primary={truncate(marking?.definition, 40)}
                        />
                      </ListItem>
                    ))}
                  </List>
                </FieldOrEmpty>
              </Grid>
              <Grid item xs={4}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Maximum shareable markings')}
                </Typography>
                <FieldOrEmpty source={markingTypes}>
                  <List>
                    {markingTypes.map((type) => {
                      const marking = maxShareableMarkingsByType.get(type);
                      if (marking) {
                        const isMarkingAllowed = checkIsMarkingAllowed(marking, allowedMarkings);
                        return (
                          <ListItem
                            key={marking.id}
                            dense={true}
                            divider={true}

                          >
                            <Typography
                              variant="h3"
                              gutterBottom={true}
                              sx={{
                                width: 100,
                              }}
                            >
                              {truncate(type, 40)}
                            </Typography>
                            {isMarkingAllowed
                              ? (
                                  <>
                                    <ListItemIcon>
                                      <MarkingIcon theme={theme} color={marking?.x_opencti_color} />
                                    </ListItemIcon>
                                    <ListItemText
                                      primary={truncate(marking.definition, 40)}
                                    />
                                  </>
                                )
                              : (
                                  <ListItemText
                                    primary={t_i18n('No restrictions')}
                                  />
                                )
                            }
                            {!isMarkingAllowed
                              && (
                                <Tooltip
                                  title={t_i18n(
                                    'The maximum shareable marking set for this definition type is not allowed for this group, so users can only share their allowed markings independently from the maximum shareable marking set.',
                                  )}
                                >
                                  <WarningOutlined color="warning" />
                                </Tooltip>
                              )
                            }
                          </ListItem>
                        );
                      }
                      if (group.not_shareable_marking_types.includes(type)) {
                        return (
                          <ListItem
                            key={type}
                            dense={true}
                            divider={true}

                          >
                            <Typography
                              variant="h3"
                              gutterBottom={true}
                              sx={{
                                width: 100,
                              }}
                            >
                              {truncate(type, 40)}
                            </Typography>
                            <ListItemText
                              primary={t_i18n('Not shareable')}
                            />
                          </ListItem>
                        );
                      }
                      return (
                        <ListItem
                          key={type}
                          dense={true}
                          divider={true}

                        >
                          <Typography
                            variant="h3"
                            gutterBottom={true}
                            sx={{
                              width: 100,
                            }}
                          >
                            {truncate(type, 40)}
                          </Typography>
                          <ListItemText
                            primary={t_i18n('No restrictions')}
                          />
                        </ListItem>
                      );
                    })}
                  </List>
                </FieldOrEmpty>
              </Grid>
            </Grid>
          </Card>
        </Grid>
        <Triggers recipientId={group.id} filterKey="authorized_members.id" />
        <GroupUsers groupId={group.id} />
      </Grid>
    </div>
  );
};

export default Group;
