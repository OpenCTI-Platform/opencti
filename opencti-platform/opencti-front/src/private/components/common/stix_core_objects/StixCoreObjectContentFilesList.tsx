import Tooltip from '@mui/material/Tooltip';
import { ListItemButton, ListItemIcon, IconButton, List, ListItemText, ListItemSecondaryAction } from '@mui/material';
import moment from 'moment/moment';
import { DeleteOutlined } from '@mui/icons-material';
import React, { useState } from 'react';
import { FileOutline, FilePdfBox, LanguageHtml5, LanguageMarkdownOutline, NoteTextOutline } from 'mdi-material-ui';
import { FileLineDeleteMutation } from '@components/common/files/FileLine';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';

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
}

interface StixCoreObjectContentFilesListProps {
  files: ContentFile[]
  currentFileId: string,
  handleSelectFile: (fileId: string) => void,
  onFileChange: (fileName?: string, isDeleted?: boolean) => void,
}

const StixCoreObjectContentFilesList = ({
  files,
  currentFileId,
  handleSelectFile,
  onFileChange,
}: StixCoreObjectContentFilesListProps) => {
  const { fld } = useFormatter();
  const [deleting, setDeleting] = useState<string | null>(null);

  const submitDelete = (
    fileName: string,
    event: React.MouseEvent<HTMLButtonElement, MouseEvent>,
  ) => {
    event.stopPropagation();
    event.preventDefault();
    setDeleting(fileName);

    // TODO use hook
    commitMutation({
      mutation: FileLineDeleteMutation,
      variables: { fileName },
      onCompleted: () => {
        setDeleting(null);
        onFileChange(fileName, true);
      },
      updater: undefined,
      onError: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      setSubmitting: undefined,
    });
  };

  return (
    <List style={{ marginBottom: 30 }}>
      {files.map((file) => {
        return (
          <Tooltip key={file.id} title={`${file.name} (${file.metaData?.mimetype ?? ''})`}>
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
                <IconButton onClick={(event) => submitDelete(file.id, event)} size="small">
                  <DeleteOutlined color="primary" fontSize="small"/>
                </IconButton>
              </ListItemSecondaryAction>
            </ListItemButton>
          </Tooltip>
        );
      })}
    </List>
  );
};

export default StixCoreObjectContentFilesList;
