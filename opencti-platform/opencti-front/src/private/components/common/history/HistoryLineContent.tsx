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
import { Link } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import { truncate } from '../../../../utils/String';
import HistoryIcon from './HistoryIcon';

interface ExternalReference {
  id: string;
  source_name: string | null | undefined;
  external_id: string | null | undefined;
  url: string | null | undefined;
  description: string | null | undefined;
}

export interface HistoryLineData {
  eventScope: string | null | undefined;
  timestamp: string | null | undefined;
  userName: string | null | undefined;
  message: string | null | undefined;
  commit: string | null | undefined;
  externalReferences: ReadonlyArray<ExternalReference>;
}

interface HistoryLineContentProps {
  data: HistoryLineData;
  isRelation: boolean;
}

/**
 * Shared presentational component for history lines.
 * Renders the icon, timestamp, message, external references, and dialogs.
 */
const HistoryLineContent = ({
  data,
  isRelation,
}: HistoryLineContentProps) => {
  const { t_i18n, nsdt } = useFormatter();
  const [open, setOpen] = useState(false);
  const [displayExternalLink, setDisplayExternalLink] = useState(false);
  const [externalLink, setExternalLink] = useState<string | null>(null);

  const hasExternalRefs = data.externalReferences.length > 0;

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const handleOpenExternalLink = (url: string) => {
    setDisplayExternalLink(true);
    setExternalLink(url);
  };
  const handleCloseExternalLink = () => {
    setDisplayExternalLink(false);
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
          invisible={data.commit == null}
        >
          <HistoryIcon
            eventScope={data.eventScope}
            eventMessage={data.message ?? ''}
            commit={data.commit}
            isRelation={isRelation}
            onClick={handleOpen}
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
        <Paper sx={{ width: '100%', height: '100%', padding: '8px 15px 0 15px', background: 0 }}>
          <div style={{
            float: 'right',
            textAlign: 'right',
            width: 180,
            paddingTop: 4,
            fontSize: 11,
          }}
          >
            {nsdt(data.timestamp)}
          </div>
          <Tooltip
            sx={{ maxWidth: '80%', lineHeight: 2, padding: 10 }}
            title={<><b>{data.userName}</b> {data.message}</>}
          >
            <div style={{
              height: '100%',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}
            >
              <MarkdownDisplay
                content={`\`${data.userName}\` ${data.message ?? ''}`}
                remarkGfmPlugin={true}
                commonmark={true}
              />
            </div>
          </Tooltip>
          {hasExternalRefs && (
            <List>
              {data.externalReferences.map((externalReference) => {
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
                      dense={true}
                      divider={true}
                      disablePadding
                      secondaryAction={(
                        <Tooltip title={t_i18n('Browse the link')}>
                          <IconButton
                            onClick={() => handleOpenExternalLink(externalReference.url!)}
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
                    component={Link}
                    key={externalReference.id}
                    to={`/dashboard/analyses/external_references/${externalReference.id}`}
                    dense={true}
                    divider={true}
                  >
                    <ListItemIcon>
                      <ItemIcon type="External-Reference" />
                    </ListItemIcon>
                    <ListItemText
                      primary={`${externalReference.source_name} ${externalReferenceId}`}
                      secondary={truncate(externalReference.description, 120)}
                    />
                  </ListItemButton>
                );
              })}
            </List>
          )}
        </Paper>
      </div>
      <Dialog
        open={open}
        onClose={handleClose}
        title={t_i18n('Commit message')}
      >
        <MarkdownDisplay
          content={data.commit ?? ''}
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
        open={displayExternalLink}
        onClose={handleCloseExternalLink}
        title={t_i18n('Do you want to browse this external link?')}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to browse this external link?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button variant="secondary" onClick={handleCloseExternalLink}>
            {t_i18n('Cancel')}
          </Button>
          <Button onClick={handleBrowseExternalLink}>
            {t_i18n('Browse the link')}
          </Button>
        </DialogActions>
      </Dialog>
    </ListItem>
  );
};

export default HistoryLineContent;
