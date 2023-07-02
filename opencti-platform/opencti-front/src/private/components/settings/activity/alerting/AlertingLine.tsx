import React, { FunctionComponent } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { BackupTableOutlined, CampaignOutlined, MoreVert } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Chip from '@mui/material/Chip';
import { DataColumns } from '../../../../../components/list_lines';
import FilterIconButton from '../../../../../components/FilterIconButton';
import { useFormatter } from '../../../../../components/i18n';
import { dayStartDate } from '../../../../../utils/Time';
import { AlertingLine_node$key } from './__generated__/AlertingLine_node.graphql';
import { AlertingPaginationQuery$variables } from './__generated__/AlertingPaginationQuery.graphql';
import AlertingPopover from './AlertingPopover';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey?.[700],
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 100,
    marginRight: 10,
  },
  chipInList2: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 140,
    textTransform: 'uppercase',
    borderRadius: '0',
  },
  chipInList3: {
    fontSize: 12,
    height: 20,
    float: 'left',
    marginRight: 10,
  },
}));

interface AlertingLineProps {
  node: AlertingLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: (
    k: string,
    id: string,
    value: Record<string, unknown>,
    event: React.KeyboardEvent
  ) => void;
  paginationOptions?: AlertingPaginationQuery$variables;
}

const alertingLineFragment = graphql`
  fragment AlertingLine_node on Trigger {
    id
    name
    trigger_type
    event_types
    description
    filters
    created
    modified
    outcomes
    period
    trigger_time
    triggers {
      id
      name
    }
  }
`;

export const AlertingLineComponent: FunctionComponent<AlertingLineProps> = ({ dataColumns, node, paginationOptions }) => {
  const classes = useStyles();
  const { t, nt } = useFormatter();
  const data = useFragment(alertingLineFragment, node);
  const filters = JSON.parse(data.filters ?? '{}');
  const outcomesOptions: Record<string, string> = {
    'f4ee7b33-006a-4b0d-b57d-411ad288653d': t('User interface'),
    '44fcf1f4-8e31-4b31-8dbc-cd6993e1b822': t('Email'),
  };
  const currentTime = data.trigger_time?.split('-') ?? [
    dayStartDate().toISOString(),
  ];
  const day = currentTime.length > 1 ? currentTime[0] : '1';
  const time = currentTime.length > 1 ? new Date(`2000-01-01T${currentTime[1]}`) : new Date(`2000-01-01T${currentTime[0]}`);
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon>
        {data.trigger_type === 'live' ? (
          <CampaignOutlined color="warning" />
        ) : (
          <BackupTableOutlined color="secondary" />
        )}
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.trigger_type.width }}
            >
              <Chip
                color={data.trigger_type === 'live' ? 'warning' : 'secondary'}
                classes={{ root: classes.chipInList2 }}
                label={
                  data.trigger_type === 'live'
                    ? t('Live trigger')
                    : t('Regular digest')
                }
                variant="outlined"
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
              style={{ width: dataColumns.outcomes.width }}
            >
              {data.outcomes && data.outcomes.length > 0
                  && data.outcomes.map<React.ReactNode>((n) => (
                    <code>{outcomesOptions[n]}</code>
                  ))
                    .reduce((prev, curr) => [prev, ', ', curr])}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.event_types.width }}
            >
              {data.event_types
                && data.event_types.map((n: string) => (
                  <Chip
                    key={n}
                    classes={{ root: classes.chipInList }}
                    color="primary"
                    variant="outlined"
                    label={t(n)}
                  />
                ))}
              {data.triggers
                && data.triggers.map((n) => (
                  <Chip
                    key={n?.id}
                    classes={{ root: classes.chipInList }}
                    color="warning"
                    variant="outlined"
                    label={n?.name}
                  />
                ))}
            </div>
            {data.trigger_type === 'live' && (
              <FilterIconButton
                filters={filters}
                dataColumns={dataColumns}
                classNameNumber={3}
                styleNumber={3}
                redirection
              />
            )}
            {data.trigger_type === 'digest' && (
              <div className={classes.bodyItem} style={{ width: dataColumns.filters.width }}>
                <Chip
                  classes={{ root: classes.chipInList3 }}
                  label={
                    <span>
                      <strong>{t('Period: ')}</strong>
                      {data.period}
                    </span>
                  }
                />
                {currentTime.length > 1 && (
                  <Chip
                    classes={{ root: classes.chipInList3 }}
                    label={
                      <span>
                        <strong>{t('Day: ')}</strong>
                        {day}
                      </span>
                    }
                  />
                )}
                {data.trigger_time && data.trigger_time.length > 0 && (
                  <Chip
                    classes={{ root: classes.chipInList3 }}
                    label={
                      <span>
                        <strong>{t('Time: ')}</strong>
                        {nt(time)}
                      </span>
                    }
                  />
                )}
              </div>
            )}
          </div>
        }
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <AlertingPopover id={data.id} paginationOptions={paginationOptions} />
      </ListItemIcon>
    </ListItem>
  );
};

export const AlertingLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
  const classes = useStyles();
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
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
                  height={20}
                />
              </div>
            ))}
          </div>
        }
      />
      <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
        <MoreVert />
      </ListItemSecondaryAction>
    </ListItem>
  );
};
