import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import { OpenInBrowserOutlined } from '@mui/icons-material';
import { ListItemButton } from '@mui/material';
import Badge from '@mui/material/Badge';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Paper from '@mui/material/Paper';
import Tooltip from '@mui/material/Tooltip';
import { useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router-dom';
import { useFormatter } from 'src/components/i18n';
import { truncate } from 'src/utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import MarkdownDisplay from '../../../../components/markdownDisplay/MarkdownDisplay';
import Transition from '../../../../components/Transition';
import { StixCoreRelationshipHistoryLine_node$key } from './__generated__/StixCoreRelationshipHistoryLine_node.graphql';
import HistoryIcon from '../history/HistoryIcon';

export const StixCoreRelationshipHistoryFragment = graphql`
  fragment StixCoreRelationshipHistoryLine_node on Log @argumentDefinitions(
    tz: {
      type: "String",
      defaultValue: null
    }
    locale: {
      type: "String",
      defaultValue: null
    }
    unit_system: {
      type: "String",
      defaultValue: null
    }
  ) {
    id
    event_type
    event_scope
    timestamp
    user {
      name
    }
    context_data(tz: $tz, locale: $locale, unit_system: $unit_system) {
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

interface StixCoreRelationshipHistoryLineProps {
  nodeRef: StixCoreRelationshipHistoryLine_node$key;
  isRelation: boolean;
}

const StixCoreRelationshipHistoryLine = ({ nodeRef, isRelation }: StixCoreRelationshipHistoryLineProps) => {
  const { t_i18n, nsdt } = useFormatter();
  const [open, setOpen] = useState(false);
  const node = useFragment<StixCoreRelationshipHistoryLine_node$key>(StixCoreRelationshipHistoryFragment, nodeRef);

  const [openExternalLink, setOpenExternalLink] = useState(false);
  const [externalLink, setExternalLink] = useState<string | null>(null);
  const externalRefs = node.context_data?.external_references ?? [];
  const hasExternalRefs = externalRefs.length > 0;

  const handleOpen = () => {
    setOpen(true);
  };
  const handleClose = () => setOpen(false);
  const handleOpenExternalLink = (url: string) => {
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

  return (
    <ListItem style={{ height: 40, padding: 0 }}>
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
          invisible={node.context_data?.commit == null}
        >
          <HistoryIcon
            eventScope={node.event_scope}
            eventMessage={node.context_data?.message ?? ''}
            commit={node.context_data?.commit}
            isRelation={isRelation}
            onCommitClick={handleOpen}
          />
        </Badge>
      </div>
      <div style={{
        flex: 1,
        width: 'auto',
        overflow: 'hidden',
        height: hasExternalRefs ? 'auto' : 40,
      }}
      >
        <Paper style={{ width: '100%', height: '100%', padding: '8px 15px 0 15px', background: 0 }}>
          <div style={{
            float: 'right',
            textAlign: 'right',
            width: 180,
            paddingTop: 4,
            fontSize: 11,
          }}
          >
            {nsdt(node.timestamp)}
          </div>
          <Tooltip
            sx={{ maxWidth: '80%', lineHeight: 2, padding: 10 }}
            title={(<><b>{node.user?.name}</b> {node.context_data?.message}</>)}
          >
            <div style={{
              height: '100%',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}
            >
              <b>{node.user?.name}</b> {node.context_data?.message}
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
                              handleOpenExternalLink(externalReference.url!)
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
        open={open}
        onClose={handleClose}
        title={t_i18n('Commit message')}
      >
        <MarkdownDisplay
          content={node.context_data?.commit ?? ''}
          remarkGfmPlugin={true}
          commonmark={true}
        />
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
    </ListItem>
  );
};

export default StixCoreRelationshipHistoryLine;
