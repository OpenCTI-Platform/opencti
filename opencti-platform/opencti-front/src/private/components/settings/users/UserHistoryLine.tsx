import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { deepOrange, deepPurple, green, indigo, lightGreen, orange, pink, red, teal, yellow } from '@mui/material/colors';
import Paper from '@mui/material/Paper';
import Avatar from '@mui/material/Avatar';
import { DeleteOutlined, LinkOffOutlined, LinkOutlined } from '@mui/icons-material';
import { LinkVariantPlus, LinkVariantRemove, Merge } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import makeStyles from '@mui/styles/makeStyles';
import { UserHistoryLine_node$key } from '@components/settings/users/__generated__/UserHistoryLine_node.graphql';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../components/i18n';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import type { Theme } from '../../../../components/Theme';
import ItemIcon from '../../../../components/ItemIcon';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    marginBottom: 5,
  },
  line: {
    content: ' ',
    display: 'block',
    position: 'absolute',
    top: 50,
    left: 20,
    width: 1,
    height: 18,
  },
  avatar: {
    float: 'left',
    width: 30,
    height: 30,
    margin: '7px 0 0 0',
  },
  content: {
    width: 'auto',
    overflow: 'hidden',
  },
  tooltip: {
    maxWidth: '80%',
    lineHeight: 2,
    padding: 10,
  },
  paper: {
    width: '100%',
    height: '100%',
    padding: '8px 15px 0 15px',
    background: 0,
  },
  description: {
    height: '100%',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  date: {
    float: 'right',
    textAlign: 'right',
    width: 180,
    paddingTop: 4,
    fontSize: 11,
  },
}));

export const userHistoryLineFragment = graphql`
  fragment UserHistoryLine_node on Log {
    id
    event_type
    event_scope
    event_status
    timestamp
    user {
      name
    }
    context_data {
      message
      commit
      external_references {
        id
        source_name
        external_id
        url
        description
      }
    }
  }
`;

interface UserHistoryLineProps {
  node: UserHistoryLine_node$key;
}

const UserHistoryLine: FunctionComponent<UserHistoryLineProps> = ({ node }) => {
  const theme = useTheme<Theme>();
  const classes = useStyles();
  const { t_i18n, nsdt } = useFormatter();
  const [open, setOpen] = useState(false);
  const log = useFragment<UserHistoryLine_node$key>(userHistoryLineFragment, node);
  const handleOpen = () => {
    setOpen(true);
  };
  const handleClose = () => {
    setOpen(false);
  };
  const renderIcon = (eventScope: string | null | undefined, isRelation: boolean, eventMessage: string | undefined, commit: string | null | undefined) => {
    if (isRelation) {
      if (eventScope === 'create') {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${pink[500]}`,
              color: theme.palette.text?.primary,
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && handleOpen()}
          >
            <LinkOutlined fontSize="small" />
          </Avatar>
        );
      }
      if (eventScope === 'delete') {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${deepPurple[500]}`,
              color: theme.palette.text?.primary,
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && handleOpen()}
          >
            <LinkOffOutlined fontSize="small" />
          </Avatar>
        );
      }
    } else {
      if (eventScope === 'create') {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${pink[500]}`,
              color: theme.palette.text?.primary,
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && handleOpen()}
          >
            {/* <ItemIcon type={eventScope} color="inherit" size="small" /> */}
            <ItemIcon type={eventScope} size="small" />
          </Avatar>
        );
      }
      if (eventScope === 'merge') {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${teal[500]}`,
              color: theme.palette.text?.primary,
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && handleOpen()}
          >
            <Merge fontSize="small" />
          </Avatar>
        );
      }
      if (
        eventScope === 'update'
        && (eventMessage?.includes('replaces') || eventMessage?.includes('updates'))
      ) {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${green[500]}`,
              color: theme.palette.text?.primary,
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && handleOpen()}
          >
            {/* <ItemIcon type={eventScope} color="inherit" size="small" /> */}
            <ItemIcon type={eventScope} size="small" />
          </Avatar>
        );
      }
      if (eventScope === 'update' && eventMessage?.includes('changes')) {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${green[500]}`,
              color: theme.palette.text?.primary,
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && handleOpen()}
          >
            {/* <ItemIcon type={eventScope} color="inherit" size="small" /> */}
            <ItemIcon type={eventScope} size="small" />
          </Avatar>
        );
      }
      if (eventScope === 'update' && eventMessage?.includes('adds')) {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${indigo[500]}`,
              color: theme.palette.text?.primary,
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && handleOpen()}
          >
            <LinkVariantPlus fontSize="small" />
          </Avatar>
        );
      }
      if (eventScope === 'update' && eventMessage?.includes('removes')) {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${deepOrange[500]}`,
              color: theme.palette.text?.primary,
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && handleOpen()}
          >
            <LinkVariantRemove fontSize="small" />
          </Avatar>
        );
      }
      if (eventScope === 'delete') {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${red[500]}`,
              color: theme.palette.text?.primary,
            }}
          >
            <DeleteOutlined fontSize="small" />
          </Avatar>
        );
      }
      if (eventScope === 'read') {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${lightGreen[500]}`,
              color: theme.palette.text?.primary,
              cursor: commit ? 'pointer' : 'auto',
            }}
          >
            {/* <ItemIcon type={eventScope} color="inherit" size="small" /> */}
            <ItemIcon type={eventScope} size="small" />
          </Avatar>
        );
      }
      if (eventScope === 'download') {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${orange[500]}`,
              color: theme.palette.text?.primary,
              cursor: commit ? 'pointer' : 'auto',
            }}
          >
            {/* <ItemIcon type={eventScope} color="inherit" size="small" /> */}
            <ItemIcon type={eventScope} size="small" />
          </Avatar>
        );
      }
    }
    return (
      <Avatar
        sx={{
          width: 25,
          height: 25,
          backgroundColor: 'transparent',
          border: `1px solid ${yellow[500]}`,
          color: theme.palette.text?.primary,
        }}
        onClick={() => commit && handleOpen()}
      >
        {/* <ItemIcon type={eventScope} color="inherit" size="small" /> */}
        <ItemIcon type={eventScope} size="small" />
      </Avatar>
    );
  };

  return (
    <div className={classes.container}>
      <div className={classes.avatar}>
        {renderIcon(log.event_scope, false, log.context_data?.message, log.context_data?.commit)}
      </div>
      <div
        className={classes.content}
        style={{
          height:
              log.context_data
              && log.context_data.external_references
              && log.context_data.external_references.length > 0
                ? 'auto'
                : 40,
        }}
      >
        <Paper classes={{ root: classes.paper }}>
          <div className={classes.date}>{nsdt(log.timestamp)}</div>
          <Tooltip
            classes={{ tooltip: classes.tooltip }}
            title={(
              <MarkdownDisplay
                content={`\`${log.user?.name}\` ${log.context_data?.message}`}
                remarkGfmPlugin={true}
                commonmark={true}
              />
            )}
          >
            <div className={classes.description}>
              <MarkdownDisplay
                content={`\`${log.user?.name}\` ${log.context_data?.message}`}
                remarkGfmPlugin={true}
                commonmark={true}
              />
            </div>
          </Tooltip>
        </Paper>
      </div>
      <div className={classes.line} />
      <Dialog
        open={open}
        slotProps={{ paper: { elevation: 1 } }}
        onClose={handleClose}
        fullWidth={true}
      >
        <DialogTitle>{t_i18n('Commit message')}</DialogTitle>
        <DialogContent>
          <MarkdownDisplay
            content={log.context_data?.message ?? '-'}
            remarkGfmPlugin={true}
            commonmark={true}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={handleClose}>
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default UserHistoryLine;
