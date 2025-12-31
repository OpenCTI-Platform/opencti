import React, { useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { deepOrange, deepPurple, green, indigo, pink, red, teal, yellow } from '@mui/material/colors';
import Paper from '@mui/material/Paper';
import Avatar from '@mui/material/Avatar';
import { AddOutlined, DeleteOutlined, EditOutlined, HelpOutlined, LinkOffOutlined, LinkOutlined, OpenInBrowserOutlined } from '@mui/icons-material';
import { LinkVariantPlus, LinkVariantRemove, Merge } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import List from '@mui/material/List';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Badge from '@mui/material/Badge';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import DialogContentText from '@mui/material/DialogContentText';
import IconButton from '@common/button/IconButton';
import ListItem from '@mui/material/ListItem';
import { ListItemButton } from '@mui/material';
import { Link } from 'react-router-dom';
import { useTheme } from '@mui/styles';
import { truncate } from 'src/utils/String';
import { useFormatter } from 'src/components/i18n';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import ItemIcon from '../../../../components/ItemIcon';
import Transition from '../../../../components/Transition';

export const StixCoreRelationshipHistoryFragment = graphql`
  fragment StixCoreRelationshipHistoryLine_node on Log {
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
      changes{
        field
        previous
        new
        added
        removed
      }
    }
  }
`;

const StixCoreRelationshipHistoryLine = ({ nodeRef, isRelation }) => {
  const theme = useTheme();
  const { t_i18n, nsdt } = useFormatter();
  const [open, setOpen] = useState(false);
  const node = useFragment(StixCoreRelationshipHistoryFragment, nodeRef);

  const [openExternalLink, setOpenExternalLink] = useState(false);
  const [externalLink, setExternalLink] = useState(null);

  const handleOpen = () => {
    setOpen(true);
  };

  const handleClose = () => setOpen(false);
  const handleOpenExternalLink = (url) => {
    setExternalLink(url);
    setOpenExternalLink(true);
  };
  const handleCloseExternalLink = () => {
    setOpenExternalLink(false);
    setExternalLink(null);
  };
  const handleBrowseExternalLink = () => {
    if (externalLink) window.open(externalLink, '_blank');
    handleCloseExternalLink();
  };
  const getIconConfig = (eventScope, eventMessage) => {
    if (isRelation) {
      if (eventScope === 'create') {
        return { color: pink[500], Icon: LinkOutlined, clickable: true };
      }
      if (eventScope === 'delete') {
        return { color: deepPurple[500], Icon: LinkOffOutlined, clickable: true };
      }
    } else {
      if (eventScope === 'create') {
        return { color: pink[500], Icon: AddOutlined, clickable: true };
      }
      if (eventScope === 'merge') {
        return { color: teal[500], Icon: Merge, clickable: true };
      }
      if (eventScope === 'update' && eventMessage.includes('replaces')) {
        return { color: green[500], Icon: EditOutlined, clickable: true };
      }
      if (eventScope === 'update' && eventMessage.includes('changes')) {
        return { color: green[500], Icon: EditOutlined, clickable: true };
      }
      if (eventScope === 'update' && eventMessage.includes('removes')) {
        return { color: deepOrange[500], Icon: LinkVariantRemove, clickable: true };
      }
      if (eventScope === 'update') {
        return { color: indigo[500], Icon: LinkVariantPlus, clickable: true };
      }
      if (eventScope === 'delete') {
        return { color: red[500], Icon: DeleteOutlined, clickable: false };
      }
    }
    return { color: yellow[500], Icon: HelpOutlined, clickable: true };
  };
  const renderIcon = (
    eventScope,
    isRelation,
    eventMessage,
    commit,
  ) => {
    const { color, Icon, clickable } = getIconConfig(eventScope, eventMessage, isRelation);
    const canClick = clickable && !!commit;
    return (
      <Avatar
        sx={{
          width: 25,
          height: 25,
          backgroundColor: 'transparent',
          border: `1px solid ${color}`,
          color: theme.palette.text.primary,
          cursor: canClick ? 'pointer' : 'auto',
        }}
        onClick={canClick ? handleOpen : undefined}
      >
        <Icon style={{ fontSize: 12 }} />
      </Avatar>
    );
  };

  const externalRefs = node.context_data?.external_references ?? [];
  const hasExternalRefs = externalRefs.length > 0;

  return (
    <div style={{
      marginBottom: 5,
    }}
    >
      <div style={{
        float: 'left',
        width: 30,
        height: 30,
        margin: '7px 0 0 0',
      }}
      >
        <Badge
          color="secondary"
          overlap="circular"
          badgeContent="M"
          invisible={node.context_data.commit == null}
        >
          {renderIcon(
            node.event_scope,
            isRelation,
            node.context_data.message,
            node.context_data.commit,
          )}
        </Badge>
      </div>
      <div
        style={{
          width: 'auto',
          overflow: 'hidden',
          height: hasExternalRefs ? 'auto' : 40 }}
      >
        <Paper style={{
          width: '100%',
          height: '100%',
          padding: '8px 15px 0 15px',
          background: 0,
        }}
        >
          <div style={{
            float: 'right',
            textAlign: 'right',
            width: 180,
            paddingTop: 4,
            fontSize: 11,
          }}
          >{nsdt(node.timestamp)}
          </div>
          <Tooltip
            style={{
              maxWidth: '80%',
              lineHeight: 2,
              padding: 10,
            }}
            title={(
              <MarkdownDisplay
                content={`\`${node.user.name}\` ${node.context_data.message}`}
                remarkGfmPlugin={true}
                commonmark={true}
              />
            )}
          >
            <div style={{
              height: '100%',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}
            >
              <MarkdownDisplay
                content={`\`${node.user.name}\` ${node.context_data.message}`}
                remarkGfmPlugin={true}
                commonmark={true}
              />
            </div>
          </Tooltip>
          {hasExternalRefs && (
            <List>
              {externalRefs.map((externalReference) => {
                const externalReferenceId = externalReference.external_id
                  ? `(${externalReference.external_id})`
                  : '';
                let externalReferenceSecondary = '';
                if (externalReference.url && externalReference.url.length > 0) {
                  externalReferenceSecondary = externalReference.url;
                } else if (
                  externalReference.description
                  && externalReference.description.length > 0
                ) {
                  externalReferenceSecondary = externalReference.description;
                }

                if (externalReference.url) {
                  return (
                    <ListItem
                      key={externalReference.id}
                      dense
                      divider
                      secondaryAction={(
                        <Tooltip title={t_i18n('Browse the link')}>
                          <IconButton
                            onClick={() =>
                              handleOpenExternalLink(externalReference.url)
                            }
                            color="primary"
                          >
                            <OpenInBrowserOutlined />
                          </IconButton>
                        </Tooltip>
                      )}
                    >
                      <ListItemButton
                        component={Link}
                        to={`/dashboard/analyses/external_references/${externalReference.id}`}
                      >
                        <ListItemIcon>
                          <ItemIcon type="External-Reference" />
                        </ListItemIcon>
                        <ListItemText
                          primary={`${externalReference.source_name} ${externalReferenceId}`}
                          secondary={truncate(externalReferenceSecondary, 90)}
                        />
                      </ListItemButton>
                    </ListItem>
                  );
                }

                return (
                  <ListItemButton
                    key={externalReference.id}
                    component={Link}
                    to={`/dashboard/analyses/external_references/${externalReference.id}`}
                    dense
                    divider
                  >
                    <ListItemIcon>
                      <ItemIcon type="External-Reference" />
                    </ListItemIcon>
                    <ListItemText
                      primary={`${externalReference.source_name} ${externalReferenceId}`}
                      secondary={truncate(
                        externalReference.description,
                        120,
                      )}
                    />
                  </ListItemButton>
                );
              })}
            </List>
          )}
        </Paper>
      </div>
      <div style={{
        content: ' ',
        display: 'block',
        position: 'absolute',
        top: 50,
        left: 20,
        width: 1,
        height: 18,
      }}
      />
      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={open}
        onClose={handleClose}
        fullWidth
      >
        <DialogTitle>{t_i18n('Commit message')}</DialogTitle>
        <DialogContent>
          <MarkdownDisplay
            content={node.context_data.commit}
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
      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={openExternalLink}
        keepMounted
        slots={{ transition: Transition }}
        onClose={handleCloseExternalLink}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to browse this external link?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button variant="secondary" onClick={handleCloseExternalLink}>{t_i18n('Cancel')}</Button>
          <Button onClick={handleBrowseExternalLink}>
            {t_i18n('Browse the link')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default StixCoreRelationshipHistoryLine;
