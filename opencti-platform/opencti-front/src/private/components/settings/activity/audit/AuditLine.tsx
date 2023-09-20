import React, { FunctionComponent, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTheme } from '@mui/styles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import Drawer from '@mui/material/Drawer';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Close } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import { DataColumns } from '../../../../../components/list_lines';
import { AuditLine_node$key } from './__generated__/AuditLine_node.graphql';
import { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import ItemIcon from '../../../../../components/ItemIcon';
import { isNotEmptyField } from '../../../../../utils/utils';
import MarkdownDisplay from '../../../../../components/MarkdownDisplay';

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
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: '10px 20px 20px 20px',
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
      entity_type
      entity_name
      message
    }
  }
`;

export const AuditLine: FunctionComponent<AuditLineProps> = ({
  dataColumns,
  node,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const { fldt } = useFormatter();
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
      {selectedLog && (
        <Drawer
          open={true}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={() => setSelectedLog(null)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={() => setSelectedLog(null)}
              size="large"
              color="primary"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6" classes={{ root: classes.title }}>
              {t('Activity raw detail')}
            </Typography>
            <div className="clearfix" />
          </div>
          <div className={classes.container}>
            <div>
              <Typography variant="h4" gutterBottom={true}>
                {t('Message')}
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
                  {t('Instance context')}
                </Typography>
                <Link to={data.context_uri}>View the element</Link>
              </div>
            )}
            <div style={{ marginTop: 16 }}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Raw data')}
              </Typography>
              <pre>{data.raw_data}</pre>
            </div>
          </div>
        </Drawer>
      )}
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        onClick={() => setSelectedLog(data.id)}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ItemIcon
            color={color}
            type={data.context_data?.entity_type ?? data.event_type}
          />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.timestamp.width }}
              >
                {fldt(data.timestamp)}
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
      </ListItem>
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
