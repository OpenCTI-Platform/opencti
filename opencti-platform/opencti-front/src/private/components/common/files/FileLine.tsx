import React, { FunctionComponent, useState } from 'react';
import { isEmpty } from 'ramda';
import moment from 'moment';
import Alert from '@mui/material/Alert';
import { createFragmentContainer, graphql, GraphQLTaggedNode } from 'react-relay';
import IconButton from '@mui/material/IconButton';
import { FileOutline, ProgressUpload } from 'mdi-material-ui';
import { DeleteOutlined, DocumentScannerOutlined, GetAppOutlined, WarningOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import CircularProgress from '@mui/material/CircularProgress';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Slide, { SlideProps } from '@mui/material/Slide';
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { PopoverProps } from '@mui/material/Popover';
import MenuItem from '@mui/material/MenuItem';
import Menu from '@mui/material/Menu';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { ListItemButton } from '@mui/material';
import useAuth from '../../../../utils/hooks/useAuth';
import FileWork from './FileWork';
import { useFormatter } from '../../../../components/i18n';
import { APP_BASE_PATH, commitMutation, MESSAGING$ } from '../../../../relay/environment';
import type { Theme } from '../../../../components/Theme';
import { FileLine_file$data } from './__generated__/FileLine_file.graphql';
import { isNotEmptyField } from '../../../../utils/utils';
import { truncate } from '../../../../utils/String';
import ItemMarkings from '../../../../components/ItemMarkings';

const Transition = React.forwardRef(({ children, ...otherProps }: SlideProps, ref) => (
  <Slide direction='up' ref={ref} {...otherProps}>{children}</Slide>
));
Transition.displayName = 'TransitionSlide';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    height: 50,
  },
  itemNested: {
    paddingLeft: theme.spacing(4),
    height: 50,
  },
  itemText: {
    whiteSpace: 'nowrap',
    marginRight: 10,
  },
  fileName: {
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
}));

export const FileLineDeleteMutation = graphql`
  mutation FileLineDeleteMutation($fileName: String) {
    deleteImport(fileName: $fileName) @deleteRecord
  }
`;

const FileLineAskDeleteMutation = graphql`
  mutation FileLineAskDeleteMutation($workId: ID!) {
    workEdit(id: $workId) {
      delete
    }
  }
`;

interface FileLineComponentProps {
  file: FileLine_file$data | undefined;
  connectors?: { data: { name: string; active: boolean } }[];
  dense: boolean;
  disableImport?: boolean;
  directDownload?: boolean;
  handleOpenImport?: (file: FileLine_file$data | undefined) => void;
  nested?: boolean;
  workNested?: boolean;
  isExternalReferenceAttachment?: boolean;
  onDelete?: () => void;
  onClick?: () => void;
  isArtifact?: boolean;
}

const FileLineComponent: FunctionComponent<FileLineComponentProps> = ({
  file,
  connectors,
  dense,
  disableImport,
  directDownload,
  handleOpenImport,
  nested,
  workNested,
  isExternalReferenceAttachment,
  onDelete,
  onClick,
  isArtifact,
}) => {
  const classes = useStyles();
  const { me } = useAuth();
  const { t_i18n, fld } = useFormatter();

  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const [displayRemove, setDisplayRemove] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [displayDownload, setDisplayDownload] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };

  const isContainsReference = isNotEmptyField(
    file?.metaData?.external_reference_id,
  );
  const isFail = file?.metaData?.errors && file.metaData.errors.length > 0;
  const isProgress = file?.uploadStatus === 'progress' || file?.uploadStatus === 'wait';
  const isOutdated = file?.uploadStatus === 'timeout';
  const file_markings = file?.metaData?.file_markings;
  const fileMarkings = me.allowed_marking?.filter(({ id }) => (file_markings ?? []).includes(id)) ?? [];

  const isImportActive = () => connectors && connectors.filter((x) => x.data.active).length > 0;
  const history = [];

  if (isOutdated) {
    const time = moment
      .duration(file.lastModifiedSinceMin, 'minutes')
      .humanize();
    history.push({
      message: `Connector execution timeout, no activity for ${time}`,
    });
  } else if (file?.metaData?.messages && file?.metaData?.errors) {
    history.push(
      ...[...file.metaData.messages.map((o) => o), ...file.metaData.errors],
    );
  }
  const toolTip = history
    .map((s) => s?.message)
    .filter((s) => !isEmpty(s))
    .join(', ');
  const encodedFilePath = encodeURIComponent(file?.id ?? '');

  const handleOpenDelete = () => {
    setDisplayDelete(true);
  };

  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };

  const handleOpenRemove = () => {
    setDisplayRemove(true);
  };

  const handleCloseRemove = () => {
    setDisplayRemove(false);
  };

  const handleCloseDownload = () => {
    setDisplayDownload(false);
  };

  const executeRemove = (
    mutation: GraphQLTaggedNode,
    variables: { fileName: string } | { workId: string },
  ) => {
    setDeleting(true);
    commitMutation({
      mutation,
      variables,
      optimisticUpdater: (store: RecordSourceSelectorProxy) => {
        if (file?.id) {
          const fileStore = store.get(file?.id);
          fileStore?.setValue(0, 'lastModifiedSinceMin');
          fileStore?.setValue('progress', 'uploadStatus');
        }
      },
      updater: (store: RecordSourceSelectorProxy) => {
        if (file?.id) {
          const fileStore = store.get(file?.id);
          fileStore?.setValue(0, 'lastModifiedSinceMin');
          fileStore?.setValue('progress', 'uploadStatus');
        }
      },
      onCompleted: () => {
        setDeleting(false);
        setDisplayDelete(false);
        setDisplayRemove(false);
        if (onDelete) {
          onDelete();
        }
        MESSAGING$.notifySuccess(t_i18n('File successfully removed'));
      },
      optimisticResponse: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };

  const handleRemoveFile = (fileId: string | undefined) => {
    if (fileId) {
      executeRemove(FileLineDeleteMutation, { fileName: fileId });
    }
  };

  const handleRemoveJob = (id: string | undefined) => {
    if (id) {
      executeRemove(FileLineAskDeleteMutation, { workId: id });
    }
  };

  const handleLink = (url: string) => {
    if (isFail || isOutdated || isProgress) return;
    handleCloseDownload();
    handleClose();
    window.location.pathname = url;
  };

  const generateIcon = () => {
    return isExternalReferenceAttachment || isContainsReference ? (
      <DocumentScannerOutlined color="primary" />
    ) : (
      <FileOutline color={nested ? 'primary' : 'inherit'} />
    );
  };
  const listUri = `${APP_BASE_PATH}/storage/${
    directDownload ? 'get' : 'view'
  }/${encodedFilePath}`;
  const isWarning = isArtifact
    || encodedFilePath.endsWith('.exe')
    || encodedFilePath.endsWith('.dll');
  const fileExtension = file?.name.substring(file?.name.lastIndexOf('.')) ?? '';
  const fileNameWithoutExtension = file?.name.substring(0, file?.name.lastIndexOf('.')) ?? '';

  let status = t_i18n('Pending');
  if (file?.metaData?.mimetype) {
    status = file.metaData.mimetype;
  }
  if (isFail) {
    status = t_i18n('Failed');
  }

  return (
    <>
      <ListItemButton
        divider={true}
        dense={dense}
        classes={{ root: nested ? classes.itemNested : classes.item }}
        rel="noopener noreferrer"
        onClick={
          onClick
          || (() => (isWarning ? setDisplayDownload(true) : handleLink(listUri)))
        }
      >
        <ListItemIcon>
          {isProgress && (
            <CircularProgress
              size={20}
              color={nested ? 'primary' : 'inherit'}
            />
          )}
          {!isProgress && (isFail || isOutdated) && (
            <Tooltip title={toolTip !== 'null' ? toolTip : ''}>
              <WarningOutlined
                color={nested ? 'primary' : 'inherit'}
                style={{ fontSize: 15, color: '#f44336', marginLeft: 4 }}
              />
            </Tooltip>
          )}
          {!isProgress && !isFail && !isOutdated && generateIcon()}
        </ListItemIcon>
        <Tooltip title={!isFail && !isOutdated ? file?.name : ''}>
          <ListItemText
            classes={{
              root: classes.itemText,
              primary: classes.fileName,
            }}
            primary={`${truncate(fileNameWithoutExtension, 80)}${fileExtension}`}
            secondary={
              <>
                {status} (
                {fld(file?.lastModified ?? moment())})
              </>
            }
          />
        </Tooltip>
        <ListItemSecondaryAction style={{ display: 'flex', alignItems: 'center' }}>
          {!isProgress && !isFail && !isOutdated && (
            <ItemMarkings variant="inList" markingDefinitions={fileMarkings} limit={1} />
          )}
          {!disableImport && (
            <Tooltip title={t_i18n('Launch an import of this file')}>
              <span>
                <IconButton
                  disabled={isProgress || !isImportActive()}
                  onClick={(event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    if (handleOpenImport && file) {
                      handleOpenImport(file);
                    }
                  }}
                  aria-haspopup="true"
                  color={nested ? 'inherit' : 'primary'}
                  size="small"
                >
                  <ProgressUpload fontSize="small" />
                </IconButton>
              </span>
            </Tooltip>
          )}
          {!directDownload && !isFail && (
            <>
              <Tooltip title={t_i18n('Download this file')}>
                <span>
                  <IconButton
                    disabled={isProgress}
                    onClick={(event) => {
                      event.preventDefault();
                      event.stopPropagation();
                      if (isWarning) {
                        handleOpen(event);
                      } else {
                        handleLink(`${APP_BASE_PATH}/storage/get/${encodedFilePath}`);
                      }
                    }}
                    aria-haspopup="true"
                    color={nested ? 'inherit' : 'primary'}
                    size="small"
                  >
                    <GetAppOutlined fontSize="small" />
                  </IconButton>
                </span>
              </Tooltip>
              <Menu
                anchorEl={anchorEl}
                open={Boolean(anchorEl)}
                onClose={handleClose}
              >
                <MenuItem
                  dense={true}
                  onClick={() => handleLink(
                    `${APP_BASE_PATH}/storage/encrypted/${encodedFilePath}`,
                  )
                  }
                >
                  {t_i18n('Encrypted archive')}
                </MenuItem>
                <MenuItem
                  dense={true}
                  onClick={() => handleLink(
                    `${APP_BASE_PATH}/storage/get/${encodedFilePath}`,
                  )
                  }
                >
                  {t_i18n('Raw file')}
                </MenuItem>
              </Menu>
            </>
          )}
          {!isExternalReferenceAttachment && (
            <>
              {isFail || isOutdated ? (
                <Tooltip title={t_i18n('Delete this file')}>
                  <span>
                    <IconButton
                      disabled={isProgress}
                      color={nested ? 'inherit' : 'primary'}
                      onClick={(event) => {
                        event.preventDefault();
                        event.stopPropagation();
                        handleOpenRemove();
                      }}
                      size="small"
                    >
                      <DeleteOutlined fontSize="small" />
                    </IconButton>
                  </span>
                </Tooltip>
              ) : (
                <Tooltip title={t_i18n('Delete this file')}>
                  <span>
                    <IconButton
                      disabled={isProgress}
                      color={nested ? 'inherit' : 'primary'}
                      onClick={(event) => {
                        event.preventDefault();
                        event.stopPropagation();
                        handleOpenDelete();
                      }}
                      size="small"
                    >
                      <DeleteOutlined fontSize="small" />
                    </IconButton>
                  </span>
                </Tooltip>
              )}
            </>
          )}
        </ListItemSecondaryAction>
      </ListItemButton>
      <FileWork file={file} nested={workNested} />
      <Dialog
        open={displayDelete}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this file?')}
            {isContainsReference && (
              <Alert
                severity="warning"
                variant="outlined"
                style={{ position: 'relative', marginTop: 20 }}
              >
                {t_i18n(
                  'This file is linked to an external reference. If you delete it, the reference will be deleted as well.',
                )}
              </Alert>
            )}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDelete} disabled={deleting}>
            {t_i18n('Cancel')}
          </Button>
          <Button
            color="secondary"
            onClick={() => handleRemoveFile(file?.id)}
            disabled={deleting}
          >
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={displayRemove}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseRemove}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to remove this job?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseRemove} disabled={deleting}>
            {t_i18n('Cancel')}
          </Button>
          <Button
            color="secondary"
            onClick={() => handleRemoveJob(file?.id)}
            disabled={deleting}
          >
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={displayDownload}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDownload}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('How do you want to download this file?')}
            <Alert
              severity="warning"
              variant="outlined"
              style={{ position: 'relative', marginTop: 20 }}
            >
              {t_i18n(
                'You are about to download a file related to an Artifact (or a binary). It might be malicious. You can download it as an encrypted archive (password: "infected") in order to protect your workstation and share it safely.',
              )}
            </Alert>
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDownload} disabled={deleting}>
            {t_i18n('Cancel')}
          </Button>
          <Button
            color="warning"
            onClick={() => handleLink(`${APP_BASE_PATH}/storage/get/${encodedFilePath}`)
            }
          >
            {t_i18n('Raw file')}
          </Button>
          <Button
            color="success"
            onClick={() => handleLink(
              `${APP_BASE_PATH}/storage/encrypted/${encodedFilePath}`,
            )
            }
          >
            {t_i18n('Encrypted archive')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

const FileLine = createFragmentContainer(FileLineComponent, {
  file: graphql`
    fragment FileLine_file on File {
      id
      name
      uploadStatus
      lastModified
      lastModifiedSinceMin
      metaData {
        mimetype
        list_filters
        external_reference_id
        file_markings
        messages {
          timestamp
          message
        }
        errors {
          timestamp
          message
        }
        labels
      }
      ...FileWork_file
    }
  `,
});

export default FileLine;
