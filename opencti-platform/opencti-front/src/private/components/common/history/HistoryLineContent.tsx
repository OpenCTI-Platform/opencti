import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import { ChevronRightOutlined, OpenInBrowserOutlined } from '@mui/icons-material';
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
import { Link } from 'react-router';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import MarkdownDisplay from '../../../../components/markdownDisplay/MarkdownDisplay';
import { truncate } from '../../../../utils/String';
import HistoryIcon from './HistoryIcon';
import { toSingleLineHistoryMessage } from './historyMessage';

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
  // The parent opens the details drawer (every operation, full values) on click
  hasDetails?: boolean;
}

/**
 * Shared presentational component for history lines.
 * Renders the icon, timestamp, message, external references, and dialogs.
 */
const HistoryLineContent = ({
  data,
  isRelation,
  hasDetails = false,
}: HistoryLineContentProps) => {
  const { t_i18n, nsdt } = useFormatter();
  const [open, setOpen] = useState(false);
  const [displayExternalLink, setDisplayExternalLink] = useState(false);
  const [externalLink, setExternalLink] = useState<string | null>(null);

  const hasExternalRefs = data.externalReferences.length > 0;
  const lineContent = `\`${data.userName ?? ''}\` ${toSingleLineHistoryMessage(data.message)}`;

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
          {hasDetails && (
            <ChevronRightOutlined
              fontSize="small"
              color="action"
              aria-label={t_i18n('Details')}
              style={{ float: 'right', marginTop: 2, marginLeft: 8 }}
            />
          )}
          <Tooltip
            slotProps={{ tooltip: { sx: { maxWidth: 600, lineHeight: 1.6, padding: '8px 10px' } } }}
            title={(
              <MarkdownDisplay
                content={lineContent}
                remarkGfmPlugin={true}
                commonmark={true}
                removeLineBreaks={true}
              />
            )}
          >
            {/* One line: inline markdown (no paragraph), cut with an ellipsis; the full message is in the tooltip and the details drawer */}
            <div style={{
              lineHeight: '24px',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}
            >
              <MarkdownDisplay
                content={lineContent}
                remarkGfmPlugin={true}
                commonmark={true}
                removeLineBreaks={true}
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
                            aria-label={t_i18n('Browse the link')}
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
