import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ToggleButton from '@mui/material/ToggleButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { useNavigate } from 'react-router-dom';
import { PopoverProps } from '@mui/material/Popover';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Security from '../../../../utils/Security';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useDeletion from '../../../../utils/hooks/useDeletion';
import FeedbackEditionContainer, { feedbackEditionQuery } from './FeedbackEditionContainer';
import { FeedbackEditionContainerQuery } from './__generated__/FeedbackEditionContainerQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

const feedbackPopoverDeletionMutation = graphql`
  mutation FeedbackPopoverDeletionMutation($id: ID!) {
    feedbackDelete(id: $id)
  }
`;

const FeedbackPopover = ({ id }: { id: string }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const navigate = useNavigate();

  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);

  const [commit] = useApiMutation(feedbackPopoverDeletionMutation);
  const queryRef = useQueryLoading<FeedbackEditionContainerQuery>(
    feedbackEditionQuery,
    { id },
  );

  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(undefined);
  };

  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };

  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete } = deletion;

  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id,
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/cases/feedbacks');
      },
    });
  };

  return (
    <div className={classes.container}>
      <ToggleButton
        value="popover"
        size="small"
        onClick={handleOpen}
      >
        <MoreVert fontSize="small" color="primary" />
      </ToggleButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>
        <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
          <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
        </Security>
      </Menu>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this feedback?')}
      />
      {queryRef && (
      <React.Suspense
        fallback={<Loader variant={LoaderVariant.inElement} />}
      >
        <FeedbackEditionContainer
          queryRef={queryRef}
          handleClose={handleClose}
          open={displayEdit}
        />
      </React.Suspense>
      )}
    </div>
  );
};

export default FeedbackPopover;
