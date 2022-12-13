import React, { FunctionComponent, useState } from 'react';
import { isEmpty, propOr } from 'ramda';
import moment from 'moment';
import { createFragmentContainer, graphql, GraphQLTaggedNode, useMutation } from 'react-relay';
import IconButton from '@mui/material/IconButton';
import { FileOutline, ProgressUpload } from 'mdi-material-ui';
import { DeleteOutlined, GetAppOutlined, WarningOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItem from '@mui/material/ListItem';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import CircularProgress from '@mui/material/CircularProgress';
import { Link } from 'react-router-dom';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Slide, { SlideProps } from '@mui/material/Slide';
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import FileWork from './FileWork';
import { useFormatter } from '../../../../components/i18n';
import { APP_BASE_PATH, commitMutation, fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { externalReferencePopoverDeletionMutation } from '../../analysis/external_references/ExternalReferencePopover';
import { Theme } from '../../../../components/Theme';
import { FileLine_file$data } from './__generated__/FileLine_file.graphql';
import { externalReferencesSearchQuery } from '../../analysis/ExternalReferences';
import { ExternalReferencesSearchQuery$data } from '../../analysis/__generated__/ExternalReferencesSearchQuery.graphql';
import {
  ExternalReferencePopoverDeletionMutation,
} from '../../analysis/external_references/__generated__/ExternalReferencePopoverDeletionMutation.graphql';

const Transition = React.forwardRef((props: SlideProps, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemNested: {
    paddingLeft: theme.spacing(4),
    height: 50,
  },
  itemText: {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
}));

export const FileLineDeleteMutation = graphql`
  mutation FileLineDeleteMutation($fileName: String) {
    deleteImport(fileName: $fileName)
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
  file: FileLine_file$data | undefined,
  connectors?: { data: { name: any; active: any; }; }[],
  dense: boolean,
  disableImport?: boolean,
  directDownload?: boolean,
  handleOpenImport?: (file: FileLine_file$data | undefined) => void,
  nested?: boolean,
  workNested?: boolean,
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
}) => {
  const classes = useStyles();
  const { t, fld } = useFormatter();

  const [displayRemove, setDisplayRemove] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const [commitMutationDeleteExternalRef] = useMutation<ExternalReferencePopoverDeletionMutation>(externalReferencePopoverDeletionMutation);

  const isFail = file?.metaData?.errors && file.metaData.errors.length > 0;
  const isProgress = file?.uploadStatus === 'progress' || file?.uploadStatus === 'wait';
  const isOutdated = file?.uploadStatus === 'timeout';
  const isImportActive = () => connectors && connectors.filter((x) => x.data.active).length > 0;
  const history = [];

  if (isOutdated) {
    const time = moment.duration(file.lastModifiedSinceMin, 'minutes').humanize();
    history.push({
      message: `Connector execution timeout, no activity for ${time}`,
    });
  } else if (file?.metaData?.messages && file?.metaData?.errors) {
    history.push(...[...file.metaData.messages.map((o) => o), ...file.metaData.errors]);
  }

  const toolTip = history.map((s) => s?.message).filter((s) => !isEmpty(s)).join(', ');
  const encodedFilePath = encodeURIComponent(file?.id ?? '');
  const listClick = `${APP_BASE_PATH}/storage/${directDownload ? 'get' : 'view'}/${encodeURIComponent(encodedFilePath)}`;

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

  const executeRemove = (mutation: GraphQLTaggedNode, variables: { fileName: string } | { workId: string }) => {
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
        MESSAGING$.notifySuccess(t('File successfully removed'));
      },
      optimisticResponse: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };

  const externalRefDelete = (fileId: string) => {
    fetchQuery(externalReferencesSearchQuery, {
      search: '',
      filters: [{ key: ['source_name'] }],
    })
      .toPromise()
      .then((data) => {
        const edges = (data as ExternalReferencesSearchQuery$data).externalReferences?.edges;
        edges?.filter((o) => o.node.fileId === fileId);
        const externalReferenceId = edges?.map((o) => o.node.id)[0];

        if (externalReferenceId) {
          commitMutationDeleteExternalRef({
            variables: {
              id: externalReferenceId,
            },
            onCompleted: () => {
              MESSAGING$.notifySuccess(t('File and associated external reference successfully removed'));
            },
            updater: undefined,
            optimisticUpdater: undefined,
            optimisticResponse: undefined,
            onError: undefined,
          });
        }
      });
  };

  const handleRemoveFile = (fileId: string | undefined) => {
    if (fileId) {
      executeRemove(FileLineDeleteMutation, { fileName: fileId });
      externalRefDelete(fileId);
    }
  };

  const handleRemoveJob = (id: string | undefined) => {
    if (id) {
      executeRemove(FileLineAskDeleteMutation, { workId: id });
    }
  };

  return (
    <div>
      <ListItem
        divider={true}
        dense={dense === true}
        classes={{ root: nested ? classes.itemNested : classes.item }}
        button={true}
        component={isOutdated ? null : Link}
        disabled={isProgress}
        to={listClick}
        target="_blank"
        rel="noopener noreferrer"
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
                style={{ fontSize: 15, color: '#f44336' }}
              />
            </Tooltip>
          )}
          {!isProgress && !isFail && !isOutdated && (
            <FileOutline color={nested ? 'primary' : 'inherit'} />
          )}
        </ListItemIcon>
        <Tooltip title={!isFail && !isOutdated ? file?.name : ''}>
          <ListItemText
            classes={{ root: classes.itemText }}
            primary={file?.name}
            secondary={fld(propOr(moment(), 'lastModified', file))}
          />
        </Tooltip>
        <ListItemSecondaryAction>
          {!disableImport && (
            <Tooltip title={t('Launch an import of this file')}>
                <span>
                  <IconButton
                    disabled={isProgress || !isImportActive()}
                    onClick={() => {
                      if (handleOpenImport && file) {
                        handleOpenImport(file);
                      }
                    }}
                    aria-haspopup="true"
                    color={nested ? 'inherit' : 'primary'}
                    size="large"
                  >
                    <ProgressUpload />
                  </IconButton>
                </span>
            </Tooltip>
          )}
          {!directDownload && !isFail && (
            <Tooltip title={t('Download this file')}>
                <span>
                  <IconButton
                    disabled={isProgress}
                    href={`${APP_BASE_PATH}/storage/get/${encodedFilePath}`}
                    aria-haspopup="true"
                    color={nested ? 'inherit' : 'primary'}
                    size="large">
                    <GetAppOutlined />
                  </IconButton>
                </span>
            </Tooltip>
          )}
          {isFail || isOutdated ? (
            <Tooltip title={t('Delete this file')}>
                <span>
                  <IconButton
                    disabled={isProgress}
                    color={nested ? 'inherit' : 'primary'}
                    onClick={handleOpenRemove}
                    size="large"
                  >
                    <DeleteOutlined />
                  </IconButton>
                </span>
            </Tooltip>
          ) : (
            <Tooltip title={t('Delete this file')}>
                <span>
                  <IconButton
                    disabled={isProgress}
                    color={nested ? 'inherit' : 'primary'}
                    onClick={handleOpenDelete}
                    size="large"
                  >
                    <DeleteOutlined />
                  </IconButton>
                </span>
            </Tooltip>
          )}
        </ListItemSecondaryAction>
      </ListItem>
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
            {t('Do you want to delete this file?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={handleCloseDelete}
            disabled={deleting}
          >
            {t('Cancel')}
          </Button>
          <Button
            color="secondary"
            onClick={() => handleRemoveFile(file?.id)}
            disabled={deleting}
          >
            {t('Delete')}
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
            {t('Do you want to remove this job?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={handleCloseRemove}
            disabled={deleting}
          >
            {t('Cancel')}
          </Button>
          <Button
            color="secondary"
            onClick={() => handleRemoveJob(file?.id)}
            disabled={deleting}
          >
            {t('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
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
      externalReferenceId
      metaData {
        mimetype
        list_filters
        messages {
          timestamp
          message
        }
        errors {
          timestamp
          message
        }
        creator {
          name
        }
        labels
      }
      ...FileWork_file
    }
  `,
});

export default FileLine;
