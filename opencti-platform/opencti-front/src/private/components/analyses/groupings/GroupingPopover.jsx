import React, { useState } from 'react';
import { useHistory } from 'react-router-dom';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer, commitMutation } from '../../../../relay/environment';
import { groupingEditionQuery } from './GroupingEdition';
import GroupingEditionContainer from './GroupingEditionContainer';
import Loader from '../../../../components/Loader';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import Transition from '../../../../components/Transition';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

const GroupingPopoverDeletionMutation = graphql`
  mutation GroupingPopoverDeletionMutation($id: ID!) {
    groupingDelete(id: $id)
  }
`;

const GroupingPopover = (props) => {
  const { id } = props;
  const history = useHistory();
  const classes = useStyles();
  const { t } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [displayEdit, setDisplayEdit] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const handleOpen = (event) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);
  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };
  const handleCloseDelete = () => setDisplayDelete(false);
  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      mutation: GroupingPopoverDeletionMutation,
      variables: { id },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        history.push('/dashboard/analyses/groupings');
      },
    });
  };
  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };
  const handleCloseEdit = () => setDisplayEdit(false);
  return (
    <div className={classes.container}>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        style={{ marginTop: 3 }}
        size="large"
      >
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenEdit}>{t('Update')}</MenuItem>
        <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
          <MenuItem onClick={handleOpenDelete}>{t('Delete')}</MenuItem>
        </Security>
      </Menu>
      <Dialog
        open={displayDelete}
        PaperProps={{ elevation: 1 }}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t('Do you want to delete this grouping?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDelete} disabled={deleting}>
            {t('Cancel')}
          </Button>
          <Button color="secondary" onClick={submitDelete} disabled={deleting}>
            {t('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
      <QueryRenderer
        query={groupingEditionQuery}
        variables={{ id }}
        render={({ props: editionProps }) => {
          if (editionProps) {
            return (
              <GroupingEditionContainer
                grouping={editionProps.grouping}
                handleClose={handleCloseEdit}
                open={displayEdit}
              />
            );
          }
          return <Loader variant="inElement" />;
        }}
      />
    </div>
  );
};

export default GroupingPopover;
