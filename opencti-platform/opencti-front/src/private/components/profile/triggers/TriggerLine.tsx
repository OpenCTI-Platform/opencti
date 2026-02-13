import React, { FunctionComponent } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { BackupTableOutlined, AlarmOnOutlined, MoreVert } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import Box from '@mui/material/Box';
import { DataColumns } from '../../../../components/list_lines';
import { TriggerLine_node$key } from './__generated__/TriggerLine_node.graphql';
import FilterIconButton from '../../../../components/FilterIconButton';
import { useFormatter } from '../../../../components/i18n';
import TriggerPopover from './TriggerPopover';
import { dayStartDate, formatTimeForToday } from '../../../../utils/Time';
import { TriggersLinesPaginationQuery$variables } from './__generated__/TriggersLinesPaginationQuery.graphql';
import { deserializeFilterGroupForFrontend, isFilterGroupNotEmpty } from '../../../../utils/filters/filtersUtils';
import { EMPTY_VALUE } from '../../../../utils/String';
import Tag from '@common/tag/Tag';
import { useTheme } from '@mui/styles';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: 40,
    display: 'flex',
    gap: '8px',
    alignItems: 'center',
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  filtersItem: {
    height: 40,
    display: 'flex',
    alignItems: 'center',
    float: 'left',
    paddingRight: 10,
  },
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
}));

interface TriggerLineProps {
  node: TriggerLine_node$key;
  dataColumns: DataColumns;
  bypassEditionRestriction: boolean;
  paginationOptions?: TriggersLinesPaginationQuery$variables;
}

const triggerLineFragment = graphql`
  fragment TriggerLine_node on Trigger {
    id
    name
    trigger_type
    event_types
    description
    filters
    created
    modified
    notifiers {
      id
      name
    }
    period
    trigger_time
    triggers {
      id
      name
    }
    isDirectAdministrator
    currentUserAccessRight
    instance_trigger
  }
`;

export const TriggerLineComponent: FunctionComponent<TriggerLineProps> = ({
  dataColumns,
  node,
  bypassEditionRestriction,
  paginationOptions,
}) => {
  const classes = useStyles();
  const theme = useTheme<Theme>();
  const { t_i18n, nt } = useFormatter();
  const data = useFragment(triggerLineFragment, node);
  const filters = deserializeFilterGroupForFrontend(data.filters);
  const currentTime = data.trigger_time?.split('-') ?? [
    dayStartDate().toISOString(),
  ];
  const day = currentTime.length > 1 ? currentTime[0] : '1';
  const time = currentTime.length > 1
    ? formatTimeForToday(currentTime[1])
    : formatTimeForToday(currentTime[0]);
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      secondaryAction={(
        <TriggerPopover
          id={data.id}
          paginationOptions={paginationOptions}
          disabled={!bypassEditionRestriction && !data.isDirectAdministrator}
        />
      )}
    >
      <ListItemIcon>
        {data.trigger_type === 'live' ? (
          <AlarmOnOutlined color="warning" />
        ) : (
          <BackupTableOutlined color="secondary" />
        )}
      </ListItemIcon>
      <ListItemText
        primary={(
          <>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.trigger_type.width }}
            >
              <Tag
                color={data.trigger_type === 'live' ? theme.palette.severity?.high : theme.palette.severity?.low}
                label={
                  data.trigger_type === 'live'
                    ? t_i18n('Live trigger')
                    : t_i18n('Regular digest')
                }
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.name.width }}
            >
              {data.name}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.notifiers.width }}
            >
              {(data.notifiers
                && data.notifiers.length > 0)
                ? data.notifiers
                    .map<React.ReactNode>((n) => <code key={n.id} style={{ marginRight: 5 }}>{n.name}</code>)
                : EMPTY_VALUE
              }
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.event_types.width }}
            >
              {data.event_types
                && data.event_types.map((n: string) => (
                  <Tag
                    key={n}
                    label={t_i18n(n)}
                  />
                ))}
              {data.triggers
                && data.triggers.map((n) => (
                  <Tag
                    key={n?.id}
                    color={theme.palette.severity?.high}
                    label={n?.name}
                  />
                ))}
            </div>
            {data.trigger_type === 'live' && (
              <div
                className={classes.filtersItem}
                style={{ width: dataColumns.filters.width }}
              >
                {isFilterGroupNotEmpty(filters) ? (
                  <FilterIconButton
                    filters={filters}
                    dataColumns={dataColumns}
                    variant="small"
                    redirection
                    entityTypes={data.instance_trigger ? ['Instance'] : ['Stix-Core-Object', 'Stix-Filtering']}
                  />
                ) : EMPTY_VALUE}
              </div>
            )}
            {data.trigger_type === 'digest' && (
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.filters.width }}
              >
                <Tag
                  label={(
                    <span>
                      <strong>{t_i18n('Period: ')}</strong>
                      {data.period}
                    </span>
                  )}
                />
                {currentTime.length > 1 && (
                  <Tag
                    label={(
                      <span>
                        <strong>{t_i18n('Day: ')}</strong>
                        {day}
                      </span>
                    )}
                  />
                )}
                {data.trigger_time && data.trigger_time.length > 0 && (
                  <Tag
                    label={(
                      <span>
                        <strong>{t_i18n('Time: ')}</strong>
                        {nt(time)}
                      </span>
                    )}
                  />
                )}
              </div>
            )}
          </>
        )}
      />
    </ListItem>
  );
};

export const TriggerLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  const classes = useStyles();
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      secondaryAction={(
        <Box sx={{ root: classes.itemIconDisabled }}>
          <MoreVert />
        </Box>
      )}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <>
            {Object.values(dataColumns).map((value) => (
              <div
                key={value.label}
                className={classes.bodyItem}
                style={{ width: value.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="50%"
                />
              </div>
            ))}
          </>
        )}
      />
    </ListItem>
  );
};
