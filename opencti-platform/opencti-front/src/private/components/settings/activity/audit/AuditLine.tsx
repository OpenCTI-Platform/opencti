import React, { FunctionComponent, useState } from 'react';
import { useTheme } from '@mui/styles';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import { ListItemButton } from '@mui/material';
import { DataColumns } from '../../../../../components/list_lines';
import { AuditLine_node$key } from './__generated__/AuditLine_node.graphql';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import ItemIcon from '../../../../../components/ItemIcon';
import { useGenerateAuditMessage } from '../../../../../utils/history';
import { HandleAddFilter } from '../../../../../utils/hooks/useLocalStorage';
import AuditDrawer from './AuditDrawer';

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
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
}));

interface AuditLineProps {
  node: AuditLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: HandleAddFilter;
}

const AuditLineFragment = graphql`
  fragment AuditLine_node on Log {
    id
    entity_type
    event_type
    event_scope
    event_status
    timestamp
    context_uri
    user {
      id
      name
    }
    context_data {
      entity_id
      entity_type
      entity_name
      message
      from_id
      to_id
    }
  }
`;

export const AuditLine: FunctionComponent<AuditLineProps> = ({
  dataColumns,
  node,
}) => {
  const classes = useStyles();
  const { fndt } = useFormatter();
  const theme = useTheme<Theme>();
  const [selectedLog, setSelectedLog] = useState<string | null>(null);
  const data = useFragment(AuditLineFragment, node);
  const message = useGenerateAuditMessage(data);
  const color = data.event_status === 'error' ? theme.palette.error.main : undefined;

  return (
    <>
      {selectedLog && (
        <AuditDrawer
          open={!!selectedLog}
          logId={selectedLog}
          onClose={() => setSelectedLog(null)}
        />
      )}
      <ListItemButton
        classes={{ root: classes.item }}
        divider={true}
        onClick={() => setSelectedLog(data.id)}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ItemIcon
            color={color}
            type={data.context_data?.entity_type ?? data.event_scope}
          />
        </ListItemIcon>
        <ListItemText
          primary={(
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.timestamp.width }}
              >
                {fndt(data.timestamp)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.user.width }}
              >
                {data.user?.name ?? '-'}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.event_type.width }}
              >
                {data.event_type}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.event_scope.width }}
              >
                {data.event_scope ?? '-'}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.message.width }}
              >
                <span style={{ color }}>
                  <b>{data.user?.name}</b> {message}
                </span>
              </div>
            </div>
          )}
        />
      </ListItemButton>
    </>
  );
};

export const AuditLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  const classes = useStyles();
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.timestamp.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.user.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.event_type.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.event_scope.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.message.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
          </div>
        )}
      />
    </ListItem>
  );
};
