import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import ToggleButton from '@mui/material/ToggleButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { PopoverProps } from '@mui/material/Popover';
import Transition from '../../../../components/Transition';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import useDeletion from '../../../../utils/hooks/useDeletion';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import ToolEditionContainer, { toolEditionQuery } from './ToolEditionContainer';
import StixCoreObjectEnrichment from '../../common/stix_core_objects/StixCoreObjectEnrichment';
import { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { ToolEditionContainerQuery } from './__generated__/ToolEditionContainerQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const toolPopoverDeletionMutation = graphql`
  mutation ToolPopoverDeletionMutation($id: ID!) {
    toolEdit(id: $id) {
      delete
    }
  }
`;

type ToolPopoverProps = {
  id: string;
};

const ToolPopover: React.FC<ToolPopoverProps> = ({ id }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();

  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);
  const [displayEnrichment, setDisplayEnrichment] = useState<boolean>(false);

  const [commit] = useApiMutation(toolPopoverDeletionMutation);
  const queryRef = useQueryLoading<ToolEditionContainerQuery>(toolEditionQuery, { id });

  const {
    deleting,
    handleOpenDelete,
    displayDelete,
    handleCloseDelete,
    setDeleting,
  } = useDeletion({ handleClose: () => setAnchorEl(null) });

  const handleOpen = (event: React.MouseEvent) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(undefined);
  };

  const handleCloseEdit = () => {
    setDisplayEdit(false);
  };
  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };

  const handleOpenEnrichment = () => {
    setDisplayEnrichment(true);
    handleClose();
  };

  const handleCloseEnrichment = () => {
    setDisplayEnrichment(false);
  };

  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: { id },
      onCompleted: () => {
        setDeleting(false);
        navigate('/dashboard/arsenal/tools');
      },
    });
  };

  return (
    <div>
      <ToggleButton value="popover" size="small" onClick={handleOpen}>
        <MoreVert fontSize="small" color="primary" />
      </ToggleButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>
        <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
          <MenuItem onClick={handleOpenEnrichment}>{t_i18n('Enrich')}</MenuItem>
        </Security>
        <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
          <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
        </Security>
      </Menu>
      <StixCoreObjectEnrichment
        stixCoreObjectId={id}
        open={displayEnrichment}
        handleClose={handleCloseEnrichment}
      />
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayDelete}
        keepMounted
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>{t_i18n('Do you want to delete this tool?')}</DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDelete} disabled={deleting}>
            {t_i18n('Cancel')}
          </Button>
          <Button color="secondary" onClick={submitDelete} disabled={deleting}>
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <ToolEditionContainer
            queryRef={queryRef}
            open={displayEdit}
            handleClose={handleCloseEdit}
          />
        </React.Suspense>
      )}
    </div>
  );
};

export default ToolPopover;
