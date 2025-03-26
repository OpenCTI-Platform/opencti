import React, { FunctionComponent, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTheme } from '@mui/styles';
import Typography from '@mui/material/Typography';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import Drawer from '@components/common/drawer/Drawer';
import { ListItemButton } from '@mui/material';
import { DataColumns } from '../../../../../components/list_lines';
import { AuditLine_node$key } from './__generated__/AuditLine_node.graphql';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import ItemIcon from '../../../../../components/ItemIcon';
import { isNotEmptyField } from '../../../../../utils/utils';
import MarkdownDisplay from '../../../../../components/MarkdownDisplay';

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
  onLabelClick: (
    k: string,
    id: string,
    value: Record<string, unknown>,
    event: React.KeyboardEvent
  ) => void;
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
    raw_data
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
  const { t_i18n, fndt } = useFormatter();
  const theme = useTheme<Theme>();
  const [selectedLog, setSelectedLog] = useState<string | null>(null);
  const data = useFragment(AuditLineFragment, node);
  const isHistoryUpdate = data.entity_type === 'History'
    && data.event_type === 'update'
    && isNotEmptyField(data.context_data?.entity_name);
  const message = `\`${data.user?.name}\` ${data.context_data?.message} ${
    isHistoryUpdate
      ? `for \`${data.context_data?.entity_name}\` (${data.context_data?.entity_type})`
      : ''
  }`;
  const color = data.event_status === 'error' ? theme.palette.error.main : undefined;
  return (
    <>
      <Drawer
        open={!!selectedLog}
        title={t_i18n('Activity raw detail')}
        onClose={() => setSelectedLog(null)}
      >
        <>
          <div>
            <Typography variant="h4" gutterBottom={true}>
              {t_i18n('Message')}
            </Typography>
            <MarkdownDisplay
              content={message}
              remarkGfmPlugin={true}
              commonmark={true}
            />
          </div>
          {data.context_uri && (
            <div style={{ marginTop: 16 }}>
              <Typography variant="h4" gutterBottom={true}>
                {t_i18n('Instance context')}
              </Typography>
              <Link to={data.context_uri}>View the element</Link>
            </div>
          )}
          <div style={{ marginTop: 16 }}>
            <Typography variant="h4" gutterBottom={true}>
              {t_i18n('Raw data')}
            </Typography>
            <pre>{data.raw_data}</pre>
          </div>
        </>
      </Drawer>
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
          primary={
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
                  <MarkdownDisplay
                    content={message}
                    remarkGfmPlugin={true}
                    commonmark={true}
                  />
                </span>
              </div>
            </div>
          }
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
        primary={
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
        }
      />
    </ListItem>
  );
};
