import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import { SupportPackageLine_node$key } from '@components/settings/support/__generated__/SupportPackageLine_node.graphql';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { FileOutline, ProgressUpload } from 'mdi-material-ui';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import IconButton from '@mui/material/IconButton';
import { DeleteOutlined, GetAppOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import CircularProgress from '@mui/material/CircularProgress';
import Chip from '@mui/material/Chip';
import { APP_BASE_PATH, handleError, MESSAGING$ } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';
import { deleteNode } from '../../../../utils/store';
import { hexToRGB } from '../../../../utils/Colors';
import { DataColumns } from '../../../../components/list_lines';

const useStyles = makeStyles(() => ({
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  item: {
    paddingLeft: 10,
    height: 50,
    cursor: 'default',
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    borderRadius: 4,
    width: 80,
  },
  label: {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
}));

type PackageStatus = 'IN_PROGRESS' | 'READY' | 'IN_ERROR' | '%future added value';

const SupportPackageLineForceZipMutation = graphql`
  mutation SupportPackageLineForceZipMutation(    
    $input: SupportPackageForceZipInput!
  ) {
      supportPackageForceZip(input: $input) {
        id
      }
  }
`;

const SupportPackageLineDeleteMutation = graphql`
  mutation SupportPackageLineDeleteMutation($id: ID!) {
    supportPackageDelete(id: $id)
  }
`;

export const supportPackageLineFragment = graphql`
  fragment SupportPackageLine_node on SupportPackage {
    id
    name
    package_status
    package_url
    package_upload_dir
    created_at
    creators {
      id
      name
    }
  }
`;

const packageStatusColors: { [key in PackageStatus]: string } = {
  IN_PROGRESS: '#303f9f',
  READY: '#4caf50',
  IN_ERROR: '#f44336',
  '%future added value': '#9e9e9e',
};

interface SupportPackageLineProps {
  dataColumns: DataColumns;
  node: SupportPackageLine_node$key;
  paginationOptions: { search: string; orderMode: string; orderBy: string };
}

const SupportPackageLine: FunctionComponent<SupportPackageLineProps> = ({
  node,
  paginationOptions,
  dataColumns,
}) => {
  const classes = useStyles();
  const { t_i18n, fd } = useFormatter();
  const data = useFragment(supportPackageLineFragment, node);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [commitDelete] = useMutation(SupportPackageLineDeleteMutation);
  const [commitForceZip] = useMutation(SupportPackageLineForceZipMutation);
  const isProgress = data?.package_status === 'IN_PROGRESS';

  const handleOpenDelete = () => {
    setDisplayDelete(true);
  };

  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };

  const submitDelete = () => {
    setDeleting(true);
    commitDelete({
      variables: {
        id: data.id,
      },
      updater: (store: RecordSourceSelectorProxy) => deleteNode(
        store,
        'Pagination_supportPackages',
        paginationOptions,
        data.id,
      ),
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
      onError: (error: Error) => {
        handleError(error);
      },
    });
  };

  const handleForceZip = () => {
    commitForceZip({
      variables: {
        input: {
          id: data.id,
        },
      },
      onCompleted: () => {
        // Check if there is a valid URL and initiate download
        if (data.package_url) {
          MESSAGING$.notifySuccess(
            'Force zip launched. Your download will start shortly.',
          );
          window.location.href = `${APP_BASE_PATH}/storage/get/${encodeURIComponent(data.package_url)}`;
        } else {
          MESSAGING$.notifyError('No download URL available.');
        }
      },
    });
  };

  return (
    <>
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon>
          {isProgress && (
            <CircularProgress
              size={20}
              color='inherit'
            />
          )}
          {!isProgress && (
            <FileOutline
              color='inherit'
            />
          )}
        </ListItemIcon>
        <ListItemText
          primary={
            <>
              <Tooltip title={data.name}>
                <div
                  className={classes.bodyItem}
                  style={{ width: dataColumns.name.width }}
                >
                  {data?.name}
                </div>
              </Tooltip>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.packageStatus.width }}
              >
                <Chip
                  classes={{ root: classes.chipInList, label: classes.label }}
                  style={{
                    color: packageStatusColors[data.package_status],
                    borderColor: packageStatusColors[data.package_status],
                    backgroundColor: hexToRGB(packageStatusColors[data.package_status]),
                  }}
                  label={data?.package_status}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.creators.width }}
              >
                {(data.creators ?? []).map((c) => c?.name).join(', ')}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created.width }}
              >
                {fd(data.created_at)}
              </div>
            </>
          }
        />
        <ListItemSecondaryAction>
          <Tooltip title={t_i18n('Force Download on this file')}>
            <span>
              <IconButton
                onClick={handleForceZip}
              >
                <ProgressUpload fontSize="small" />
              </IconButton>
            </span>
          </Tooltip>
          <Tooltip title={t_i18n('Download this file')}>
            <span>
              <IconButton
                disabled={isProgress || !data.package_url}
                href={`${APP_BASE_PATH}/storage/get/${encodeURIComponent(
                  data?.package_url || '',
                )}`}
              >
                <GetAppOutlined fontSize="small" />
              </IconButton>
            </span>
          </Tooltip>
          <Tooltip title={t_i18n('Delete this support package')}>
            <span>
              <IconButton
                disabled={false}
                color='inherit'
                onClick={handleOpenDelete}
                size="small"
              >
                <DeleteOutlined fontSize="small" />
              </IconButton>
            </span>
          </Tooltip>
        </ListItemSecondaryAction>
      </ListItem>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayDelete}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this support package?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDelete}>
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitDelete}
            color="secondary"
            disabled={deleting}
          >
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default SupportPackageLine;
