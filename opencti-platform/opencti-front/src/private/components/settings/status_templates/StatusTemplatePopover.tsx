import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Drawer from '@mui/material/Drawer';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { PopoverProps } from '@mui/material/Popover';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StatusTemplateEdition from './StatusTemplateEdition';
import { deleteNode } from '../../../../utils/store';
import { Theme } from '../../../../components/Theme';
import Transition from '../../../../components/Transition';
import { StatusTemplatePopoverEditionQuery$data } from './__generated__/StatusTemplatePopoverEditionQuery.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    margin: 0,
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
}));

const statusTemplatePopoverDeletionMutation = graphql`
  mutation StatusTemplatePopoverDeletionMutation($id: ID!) {
    statusTemplateDelete(id: $id)
  }
`;

const statusTemplateEditionQuery = graphql`
  query StatusTemplatePopoverEditionQuery($id: String!) {
    statusTemplate(id: $id) {
      ...StatusTemplateEdition_statusTemplate
    }
  }
`;

interface StatusTemplatePopoverProps {
  statusTemplateId: string,
  paginationOptions: { search: string, orderMode: string, orderBy: string },
}

const StatusTemplatePopover: FunctionComponent<StatusTemplatePopoverProps> = ({ statusTemplateId, paginationOptions }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);
  const [displayDelete, setDisplayDelete] = useState<boolean>(false);
  const [deleting, setDeleting] = useState<boolean>(false);

  const handleOpen = (event: React.MouseEvent) => setAnchorEl(event.currentTarget);

  const handleClose = () => setAnchorEl(null);

  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    handleClose();
  };

  const handleCloseUpdate = () => setDisplayUpdate(false);

  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };

  const handleCloseDelete = () => setDisplayDelete(false);

  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      mutation: statusTemplatePopoverDeletionMutation,
      variables: {
        id: statusTemplateId,
      },
      updater: (store: RecordSourceSelectorProxy) => deleteNode(store, 'Pagination_statusTemplates', paginationOptions, statusTemplateId),
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };

  return (
    <div className={classes.container}>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        size="large"
      >
        <MoreVert />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
      >
        <MenuItem onClick={handleOpenUpdate}>
          {t('Update')}
        </MenuItem>
        <MenuItem onClick={handleOpenDelete}>
          {t('Delete')}
        </MenuItem>
      </Menu>
      <Drawer
        open={displayUpdate}
        anchor="right"
        sx={{ zIndex: 1202 }}
        elevation={1}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleCloseUpdate}
      >
        <QueryRenderer
          query={statusTemplateEditionQuery}
          variables={{ id: statusTemplateId }}
          render={({ props }: { props: StatusTemplatePopoverEditionQuery$data }) => {
            if (props && props.statusTemplate) {
              return (
                <StatusTemplateEdition
                  statusTemplate={props.statusTemplate}
                  handleClose={handleCloseUpdate}
                />
              );
            }
            return <Loader variant={LoaderVariant.inElement} />;
          }}
        />
      </Drawer>
      <Dialog
        open={displayDelete}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t('Do you want to delete this status template?')}
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
            onClick={submitDelete}
            disabled={deleting}
          >
            {t('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default StatusTemplatePopover;
