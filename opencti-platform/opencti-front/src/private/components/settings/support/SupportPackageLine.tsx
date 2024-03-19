import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import { SupportPackageLine_node$key } from '@components/settings/support/__generated__/SupportPackageLine_node.graphql';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { FileOutline } from 'mdi-material-ui';
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
import { APP_BASE_PATH, handleError } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';
import { deleteNode } from '../../../../utils/store';

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
}));

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
  }
`;

interface SupportPackageLineProps {
  node: SupportPackageLine_node$key;
  paginationOptions: { search: string; orderMode: string; orderBy: string };
}

const SupportPackageLine: FunctionComponent<SupportPackageLineProps> = ({
  node,
  paginationOptions,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const data = useFragment(supportPackageLineFragment, node);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [commitDelete] = useMutation(SupportPackageLineDeleteMutation);
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
            <div>
              <div className={classes.bodyItem}>
                {data?.name}
              </div>
            </div>
            }
        />
        <ListItemSecondaryAction>
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
