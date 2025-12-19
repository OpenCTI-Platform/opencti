import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@common/button/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql, useQueryLoader } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { TriggersLinesPaginationQuery$variables } from './__generated__/TriggersLinesPaginationQuery.graphql';
import { deleteNode } from '../../../../utils/store';
import TriggerEditionContainer, { triggerKnowledgeEditionQuery } from './TriggerEditionContainer';
import { TriggerEditionContainerKnowledgeQuery } from './__generated__/TriggerEditionContainerKnowledgeQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

export const TriggerPopoverDeletionMutation = graphql`
  mutation TriggerPopoverDeletionMutation($id: ID!) {
    triggerKnowledgeDelete(id: $id)
  }
`;

const TriggerPopover = ({
  id,
  paginationOptions,
  disabled,
}: {
  id: string;
  paginationOptions?: TriggersLinesPaginationQuery$variables;
  disabled: boolean;
}) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);
  const [commit] = useApiMutation(TriggerPopoverDeletionMutation);
  const [queryRef, loadQuery] = useQueryLoader<TriggerEditionContainerKnowledgeQuery>(triggerKnowledgeEditionQuery);
  const handleOpen = (event: React.MouseEvent<HTMLElement>) => {
    loadQuery({ id }, { fetchPolicy: 'store-and-network' });
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => setAnchorEl(null);
  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete, handleCloseDelete } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id,
      },
      updater: (store) => {
        deleteNode(store, 'Pagination_triggersKnowledge', paginationOptions, id);
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
    });
  };
  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };
  const handleCloseEdit = () => setDisplayEdit(false);
  return (
    <>
      <Tooltip title={disabled ? t_i18n('This trigger/digest has been shared with you and you are not able to modify or delete it') : ''}>
        <IconButton
          onClick={handleOpen}
          aria-haspopup="true"
          style={{ marginTop: 3 }}
          disabled={disabled}
          color="primary"
        >
          <MoreVert />
        </IconButton>
      </Tooltip>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this trigger?')}
      />
      <Drawer
        title={t_i18n('Update a trigger')}
        open={displayEdit}
        onClose={handleCloseEdit}
      >
        {queryRef && (
          <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <TriggerEditionContainer
              queryRef={queryRef}
              handleClose={handleCloseEdit}
              paginationOptions={paginationOptions}
            />
          </React.Suspense>
        )}
      </Drawer>
    </>
  );
};

export default TriggerPopover;
