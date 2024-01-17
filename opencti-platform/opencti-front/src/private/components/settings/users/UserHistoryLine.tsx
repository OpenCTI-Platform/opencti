import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { green, pink, deepOrange, yellow, teal, deepPurple, indigo, red, lightGreen, orange } from '@mui/material/colors';
import Paper from '@mui/material/Paper';
import Avatar from '@mui/material/Avatar';
import { AddOutlined, EditOutlined, HelpOutlined, LinkOutlined, LinkOffOutlined, DeleteOutlined, VisibilityOutlined, DownloadOutlined } from '@mui/icons-material';
import { LinkVariantPlus, LinkVariantRemove, Merge } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import makeStyles from '@mui/styles/makeStyles';
import { UserHistoryLine_node$key } from '@components/settings/users/__generated__/UserHistoryLine_node.graphql';
import { useFormatter } from '../../../../components/i18n';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import type { Theme } from '../../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    marginBottom: 20,
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
    width: 40,
    height: 40,
    margin: '5px 10px 0 0',
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
    backgroundColor: theme.palette.background.shadow,
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

const userHistoryLineFragment = graphql`
  fragment UserHistoryLine_node on Log {
    id
    event_type
    event_scope
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
  node: UserHistoryLine_node$key,
}

const UserHistoryLine: FunctionComponent<UserHistoryLineProps> = ({ node }) => {
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
              width: 30,
              height: 30,
              backgroundColor: pink[500],
              color: '#ffffff',
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
              width: 30,
              height: 30,
              backgroundColor: deepPurple[500],
              color: '#ffffff',
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
              width: 30,
              height: 30,
              backgroundColor: pink[500],
              color: '#ffffff',
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && handleOpen()}
          >
            <AddOutlined fontSize="small" />
          </Avatar>
        );
      }
      if (eventScope === 'merge') {
        return (
          <Avatar
            sx={{
              width: 30,
              height: 30,
              backgroundColor: teal[500],
              color: '#ffffff',
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
              width: 30,
              height: 30,
              backgroundColor: green[500],
              color: '#ffffff',
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && handleOpen()}
          >
            <EditOutlined fontSize="small" />
          </Avatar>
        );
      }
      if (eventScope === 'update' && eventMessage?.includes('changes')) {
        return (
          <Avatar
            sx={{
              width: 30,
              height: 30,
              backgroundColor: green[500],
              color: '#ffffff',
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && handleOpen()}
          >
            <EditOutlined fontSize="small" />
          </Avatar>
        );
      }
      if (eventScope === 'update' && eventMessage?.includes('adds')) {
        return (
          <Avatar
            sx={{
              width: 30,
              height: 30,
              backgroundColor: indigo[500],
              color: '#ffffff',
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
              width: 30,
              height: 30,
              backgroundColor: deepOrange[500],
              color: '#ffffff',
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
              width: 30,
              height: 30,
              backgroundColor: red[500],
              color: '#ffffff',
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
              width: 30,
              height: 30,
              backgroundColor: lightGreen[700],
              color: '#ffffff',
            }}
          >
            <VisibilityOutlined fontSize="small" />
          </Avatar>
        );
      }
      if (eventScope === 'download') {
        return (
          <Avatar
            sx={{
              width: 30,
              height: 30,
              backgroundColor: orange[800],
              color: '#ffffff',
            }}
          >
            <DownloadOutlined fontSize="small" />
          </Avatar>
        );
      }
    }
    return (
      <Avatar
        sx={{
          width: 30,
          height: 30,
          backgroundColor: yellow[500],
          color: '#ffffff',
        }}
        onClick={() => commit && handleOpen()}
      >
        <HelpOutlined fontSize="small" />
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
            title={
              <MarkdownDisplay
                content={`\`${log.user?.name}\` ${log.context_data?.message}`}
                remarkGfmPlugin={true}
                commonmark={true}
              />
              }
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
        PaperProps={{ elevation: 1 }}
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
          <Button color="primary" onClick={handleClose}>
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default UserHistoryLine;
