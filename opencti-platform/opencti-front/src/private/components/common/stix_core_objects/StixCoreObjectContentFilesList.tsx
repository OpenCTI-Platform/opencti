import Tooltip from '@mui/material/Tooltip';
import { ListItemButton, ListItemIcon, IconButton, List, ListItemText, ListItemSecondaryAction } from '@mui/material';
import moment from 'moment/moment';
import { MoreVert } from '@mui/icons-material';
import React, { useState, MouseEvent, Fragment } from 'react';
import { FileOutline, FilePdfBox, LanguageHtml5, LanguageMarkdownOutline, NoteTextOutline } from 'mdi-material-ui';
import { FileLineDeleteMutation as deleteMutation } from '@components/common/files/FileLine';
import { FileLineDeleteMutation } from '@components/common/files/__generated__/FileLineDeleteMutation.graphql';
import MenuItem from '@mui/material/MenuItem';
import Menu from '@mui/material/Menu';
import axios from 'axios';
import { Link } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { htmlToPdf, htmlToPdfReport } from '../../../../utils/htmlToPdf';
import { APP_BASE_PATH, MESSAGING$ } from '../../../../relay/environment';

const renderIcon = (mimeType: string) => {
  switch (mimeType) {
    case 'text/plain':
      return <NoteTextOutline />;
    case 'application/pdf':
      return <FilePdfBox />;
    case 'text/markdown':
      return <LanguageMarkdownOutline />;
    case 'text/html':
      return <LanguageHtml5 />;
    default:
      return <FileOutline />;
  }
};

export interface ContentFile {
  id: string
  lastModified: string
  name: string
  metaData: {
    mimetype: string | null | undefined
  } | null | undefined
  objectMarking?: readonly {
    readonly id: string;
    readonly representative: {
      readonly main: string;
    };
  }[];
}

interface StixCoreObjectContentFilesListProps {
  files: ContentFile[],
  stixCoreObjectName: string,
  currentFileId: string,
  handleSelectFile: (fileId: string) => void,
  onFileChange: (fileName?: string, isDeleted?: boolean) => void,
}

const StixCoreObjectContentFilesList = ({
  files,
  currentFileId,
  stixCoreObjectName,
  handleSelectFile,
  onFileChange,
}: StixCoreObjectContentFilesListProps) => {
  const { fld, t_i18n } = useFormatter();
  const [deleting, setDeleting] = useState<string | null>(null);

  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [menuFile, setMenuFile] = useState<ContentFile | null>(null);
  const openPopover = (e: MouseEvent<HTMLButtonElement>, file: ContentFile) => {
    e.stopPropagation();
    setAnchorEl(e.currentTarget);
    setMenuFile(file);
  };
  const closePopover = () => {
    setAnchorEl(null);
    setMenuFile(null);
  };

  const [commitDelete] = useApiMutation<FileLineDeleteMutation>(deleteMutation);
  const submitDelete = (fileId: string) => {
    closePopover();
    setDeleting(fileId);
    commitDelete({
      variables: { fileName: fileId },
      onCompleted: () => {
        setDeleting(null);
        onFileChange(fileId, true);
      },
    });
  };

  const downloadPdf = async (file: ContentFile) => {
    closePopover();
    const { id } = file;
    const url = `${APP_BASE_PATH}/storage/view/${encodeURIComponent(id)}`;

    try {
      const { data } = await axios.get(url);
      const currentName = (id.split('/').pop() ?? '').split('.')[0];

      if (id.startsWith('fromTemplate')) {
        const markings = file.objectMarking?.map((m) => m.representative.main) ?? [];
        htmlToPdfReport(stixCoreObjectName, data, currentName, markings).download(`${currentName}.pdf`);
      } else {
        htmlToPdf(id, data).download(`${currentName}.pdf`);
      }
    } catch (e) {
      MESSAGING$.notifyError('Error trying to download in PDF');
    }
  };

  return (
    <List>
      {files.map((file) => (
        <Fragment key={file.id}>
          <Tooltip title={`${file.name} (${file.metaData?.mimetype ?? ''})`}>
            <ListItemButton
              dense={true}
              divider={true}
              selected={file.id === currentFileId}
              onClick={() => handleSelectFile(file.id)}
              disabled={deleting === file.id}
            >
              <ListItemIcon>
                {renderIcon(file.metaData?.mimetype ?? '')}
              </ListItemIcon>
              <ListItemText
                sx={{
                  '.MuiListItemText-primary': {
                    overflowX: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    marginRight: '20px',
                  },
                }}
                primary={file.name}
                secondary={fld(file.lastModified ?? moment())}
              />
              <ListItemSecondaryAction>
                <IconButton
                  onClick={(e) => openPopover(e, file)}
                  aria-haspopup="true"
                  color="primary"
                  size="small"
                >
                  <MoreVert />
                </IconButton>
              </ListItemSecondaryAction>
            </ListItemButton>
          </Tooltip>
        </Fragment>
      ))}

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={closePopover}
      >
        {menuFile && (
          <>
            <MenuItem
              component={Link}
              to={`${APP_BASE_PATH}/storage/get/${encodeURIComponent(menuFile.id)}`}
              onClick={closePopover}
              target="_blank"
              rel="noopener noreferrer"
            >
              {t_i18n('Download file')}
            </MenuItem>
            {menuFile.metaData?.mimetype !== 'application/pdf' && (
              <MenuItem onClick={() => downloadPdf(menuFile)}>
                {t_i18n('Download in PDF')}
              </MenuItem>
            )}
            <MenuItem onClick={() => submitDelete(menuFile.id)}>
              {t_i18n('Delete')}
            </MenuItem>
          </>
        )}
      </Menu>
    </List>
  );
};

export default StixCoreObjectContentFilesList;
