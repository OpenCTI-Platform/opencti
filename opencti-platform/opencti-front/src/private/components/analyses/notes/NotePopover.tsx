import React, { FunctionComponent, useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ToggleButton from '@mui/material/ToggleButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import StixCoreObjectEnrollPlaybook from '@components/common/stix_core_objects/StixCoreObjectEnrollPlaybook';
import StixCoreObjectEnrichment from '@components/common/stix_core_objects/StixCoreObjectEnrichment';
import StixCoreObjectMenuItemUnderEE from '@components/common/stix_core_objects/StixCoreObjectMenuItemUnderEE';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { noteEditionQuery } from './NoteEdition';
import NoteEditionContainer from './NoteEditionContainer';
import Security, { CollaborativeSecurity } from '../../../../utils/Security';
import { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE_KNDELETE, SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import { StixCoreObjectOrStixCoreRelationshipNoteCard_node$data } from './__generated__/StixCoreObjectOrStixCoreRelationshipNoteCard_node.graphql';
import { NoteEditionContainerQuery$data } from './__generated__/NoteEditionContainerQuery.graphql';
import { deleteNode } from '../../../../utils/store';
import { StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables } from './__generated__/StixCoreObjectOrStixCoreRelationshipNotesCardsQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

const NotePopoverDeletionMutation = graphql`
  mutation NotePopoverDeletionMutation($id: ID!) {
    noteEdit(id: $id) {
      delete
    }
  }
`;

interface NotePopoverProps {
  id: string;
  handleOpenRemoveExternal?: () => void;
  size?: 'medium' | 'large' | 'small' | undefined;
  note: StixCoreObjectOrStixCoreRelationshipNoteCard_node$data;
  paginationOptions?: StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables;
}

const NotePopover: FunctionComponent<NotePopoverProps> = ({
  id,
  handleOpenRemoveExternal,
  size = 'large',
  note,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();

  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);
  const [displayEnroll, setDisplayEnroll] = useState(false);

  const handleOpen = (event: React.MouseEvent<HTMLElement>) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);

  const [commit] = useApiMutation(NotePopoverDeletionMutation);

  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete, handleCloseDelete } = deletion;

  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id,
      },
      updater: (store) => {
        if (paginationOptions) {
          deleteNode(store, 'Pagination_notes', paginationOptions, note.id);
        }
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        if (handleOpenRemoveExternal) {
          handleCloseDelete();
        } else {
          navigate('/dashboard/analyses/notes');
        }
      },
    });
  };

  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };

  const handleCloseEdit = () => setDisplayEdit(false);

  const handleOpenRemove = () => {
    if (handleOpenRemoveExternal) {
      handleOpenRemoveExternal();
    }
    handleClose();
  };

  const handleOpenEnroll = () => {
    setDisplayEnroll(true);
    handleClose();
  };

  const handleCloseEnroll = () => {
    setDisplayEnroll(false);
  };

  return (
    <>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>
        {handleOpenRemoveExternal && (
          <MenuItem onClick={handleOpenRemove}>
            {t_i18n('Remove from this entity')}
          </MenuItem>
        )}
        <StixCoreObjectMenuItemUnderEE
          setOpen={handleOpenEnroll}
          title={t_i18n('Enroll in playbook')}
          needs={[KNOWLEDGE_KNENRICHMENT, SETTINGS_SETACCESSES]}
          matchAll
        />
        <CollaborativeSecurity
          data={note}
          needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}
        >
          <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
        </CollaborativeSecurity>
      </Menu>

      <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
        <StixCoreObjectEnrichment stixCoreObjectId={id} onClose={undefined} isOpen={undefined} />
      </Security>

      <StixCoreObjectEnrollPlaybook stixCoreObjectId={id} open={displayEnroll} handleClose={handleCloseEnroll} />

      <ToggleButton
        onClick={handleOpen}
        aria-haspopup="true"
        value="popover"
        size={size}
        color="primary"
      >
        <MoreVert fontSize="small" color="primary" />
      </ToggleButton>

      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this note?')}
      />
      <QueryRenderer
        query={noteEditionQuery}
        variables={{ id }}
        render={({ props }: { props: NoteEditionContainerQuery$data }) => {
          if (props && props.note) {
            return (
              <NoteEditionContainer
                note={props.note}
                handleClose={handleCloseEdit}
                open={displayEdit}
              />
            );
          }
          return <div />;
        }}
      />
    </>
  );
};

export default NotePopover;
