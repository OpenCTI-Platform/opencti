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
import useDeletion from 'src/utils/hooks/useDeletion';
import DeleteDialog from 'src/components/DeleteDialog';
import StixCoreObjectFileExport, { BUILT_IN_FROM_FILE_TEMPLATE } from '@components/common/stix_core_objects/StixCoreObjectFileExport';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { htmlToPdf } from '../../../../utils/htmlToPdf';
import { APP_BASE_PATH, MESSAGING$ } from '../../../../relay/environment';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';

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
  stixCoreObjectId: string,
  stixCoreObjectType: string,
  currentFileId: string,
  handleSelectFile: (fileId: string) => void,
  onFileChange: (fileName?: string, isDeleted?: boolean) => void,
}

const StixCoreObjectContentFilesList = ({
  files,
  stixCoreObjectId,
  stixCoreObjectType,
  currentFileId,
  handleSelectFile,
  onFileChange,
}: StixCoreObjectContentFilesListProps) => {
  const { fld, t_i18n } = useFormatter();
  const deletion = useDeletion({});

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
  const submitDelete = () => {
    if (!menuFile?.id) return;
    deletion.handleCloseDelete();
    closePopover();
    deletion.setDeleting(true);
    commitDelete({
      variables: { fileName: menuFile.id },
      onCompleted: () => {
        deletion.setDeleting(false);
        onFileChange(menuFile.id, true);
      },
    });
  };

  const handleDelete = () => deletion.handleOpenDelete();

  const downloadPdf = async (file: ContentFile) => {
    closePopover();
    const { id } = file;
    const url = `${APP_BASE_PATH}/storage/view/${encodeURIComponent(id)}`;

    try {
      const { data } = await axios.get(url);
      const currentName = (id.split('/').pop() ?? '').split('.')[0];
      htmlToPdf(id, data).download(`${currentName}.pdf`);
    } catch (e) {
      MESSAGING$.notifyError(t_i18n('Error trying to download in PDF'));
    }
  };

  const filesFromTemplate = (files ?? []).map((f) => ({
    label: f.name,
    value: f.id,
    fileMarkings: (f.objectMarking ?? []).map((m) => ({
      id: m.id,
      name: getMainRepresentative(m),
    })),
  }));

  const handleClose = () => {
    deletion.handleCloseDelete();
    closePopover();
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
              disabled={deletion.deleting}
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
            {!file.id.startsWith('fromTemplate') && (
              <MenuItem onClick={() => downloadPdf(file)}>
                {t_i18n('Download in PDF')}
              </MenuItem>
            )}
            {file.id.startsWith('fromTemplate') && (
              <StixCoreObjectFileExport
                onClose={() => setAnchorEl(null)}
                scoId={stixCoreObjectId}
                scoEntityType={stixCoreObjectType}
                filesFromTemplate={filesFromTemplate}
                defaultValues={{
                  connector: BUILT_IN_FROM_FILE_TEMPLATE.value,
                  format: 'application/pdf',
                  templateFile: file.id,
                }}
                OpenFormComponent={({ onOpen }) => (
                  <Tooltip title={t_i18n('Generate a PDF export')}>
                    <MenuItem onClick={onOpen}>
                      {t_i18n('Generate a PDF export')}
                    </MenuItem>
                  </Tooltip>
                )}
              />
            )}
            <MenuItem onClick={handleDelete}>
              {t_i18n('Delete')}
            </MenuItem>
            <DeleteDialog
              title={t_i18n('Are you sure you want to delete this file?')}
              deletion={deletion}
              onClose={handleClose}
              submitDelete={submitDelete}
            />
          </>
        )}
      </Menu>
    </List>
  );
};

export default StixCoreObjectContentFilesList;
