import { FunctionComponent, useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql, useFragment } from 'react-relay';
import StixCoreObjectEnrollPlaybook from '@components/common/stix_core_objects/StixCoreObjectEnrollPlaybook';
import StixCoreObjectEnrichment from '@components/common/stix_core_objects/StixCoreObjectEnrichment';
import StixCoreObjectMenuItemUnderEE from '@components/common/stix_core_objects/StixCoreObjectMenuItemUnderEE';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { noteEditionQuery } from './NoteEdition';
import NoteEditionContainer from './NoteEditionContainer';
import Security, { CollaborativeSecurity } from '../../../../utils/Security';
import { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE_KNDELETE, SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import { NoteEditionContainerQuery$data } from './__generated__/NoteEditionContainerQuery.graphql';
import { deleteNode } from '../../../../utils/store';
import { StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables } from './__generated__/StixCoreObjectOrStixCoreRelationshipNotesCardsQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';
import IconButton from '../../../../components/common/button/IconButton';
import { noteMutationRelationDelete } from './AddNotesLines';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { NotePopoverFragment$key } from './__generated__/NotePopoverFragment.graphql';

const notePopoverFragment = graphql`
  fragment NotePopoverFragment on Note {
    id
    createdBy {
      id
    }
  }
`;

const NotePopoverDeletionMutation = graphql`
  mutation NotePopoverDeletionMutation($id: ID!) {
    noteEdit(id: $id) {
      delete
    }
  }
`;

interface NotePopoverProps {
  entityId: string;
  data: NotePopoverFragment$key;
  paginationOptions: StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables;
}

const NotePopover: FunctionComponent<NotePopoverProps> = ({
  entityId,
  data,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const note = useFragment(notePopoverFragment, data);

  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [displayEdit, setDisplayEdit] = useState(false);
  const [displayEnrich, setDisplayEnrich] = useState(false);
  const [displayEnroll, setDisplayEnroll] = useState(false);

  const [commitDelete] = useApiMutation(NotePopoverDeletionMutation);
  const [commitEntityRemove] = useApiMutation(noteMutationRelationDelete);

  const closeMenu = () => setAnchorEl(null);
  const noteDeletion = useDeletion({ handleClose: closeMenu });
  const noteEntityRemoval = useDeletion({ handleClose: closeMenu });

  const updater = (store: RecordSourceSelectorProxy) => {
    deleteNode(store, 'Pagination_notes', paginationOptions, note.id);
  };

  const submitNoteEntityRemove = () => {
    commitEntityRemove({
      variables: {
        id: note.id,
        toId: entityId,
        relationship_type: 'object',
      },
      updater,
      onCompleted: () => {
        noteEntityRemoval.setDeleting(false);
        noteEntityRemoval.handleCloseDelete();
      },
    });
  };

  const submitNoteDelete = () => {
    noteDeletion.setDeleting(true);
    commitDelete({
      variables: { id: note.id },
      updater,
      onCompleted: () => {
        noteDeletion.setDeleting(false);
        noteDeletion.handleCloseDelete();
      },
    });
  };

  const openEditDrawer = () => {
    setDisplayEdit(true);
    closeMenu();
  };

  const openEnrollDrawer = () => {
    setDisplayEnroll(true);
    closeMenu();
  };

  const openEnrichDrawer = () => {
    setDisplayEnrich(true);
    closeMenu();
  };

  const openRemoveFromEntity = () => {
    noteEntityRemoval.handleOpenDelete();
    closeMenu();
  };

  const openDeleteNote = () => {
    noteDeletion.handleOpenDelete();
    closeMenu();
  };

  return (
    <>
      <IconButton onClick={(e) => setAnchorEl(e.currentTarget)}>
        <MoreVert fontSize="small" color="primary" />
      </IconButton>

      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={closeMenu}>
        <MenuItem onClick={openEditDrawer}>
          {t_i18n('Update')}
        </MenuItem>
        <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
          <MenuItem onClick={openEnrichDrawer}>
            {t_i18n('Enrichment')}
          </MenuItem>
        </Security>
        <StixCoreObjectMenuItemUnderEE
          setOpen={openEnrollDrawer}
          title={t_i18n('Enroll in playbook')}
          needs={[KNOWLEDGE_KNENRICHMENT, SETTINGS_SETACCESSES]}
          matchAll
        />
        <MenuItem onClick={openRemoveFromEntity}>
          {t_i18n('Remove from this entity')}
        </MenuItem>
        <CollaborativeSecurity
          data={note}
          needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}
        >
          <MenuItem onClick={openDeleteNote}>
            {t_i18n('Delete')}
          </MenuItem>
        </CollaborativeSecurity>
      </Menu>

      <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
        <StixCoreObjectEnrichment
          stixCoreObjectId={note.id}
          onClose={() => setDisplayEnrich(false)}
          isOpen={displayEnrich}
        />
      </Security>

      <StixCoreObjectEnrollPlaybook
        stixCoreObjectId={note.id}
        open={displayEnroll}
        handleClose={() => setDisplayEnroll(false)}
      />

      <DeleteDialog
        deletion={noteEntityRemoval}
        submitDelete={submitNoteEntityRemove}
        message={t_i18n('Do you want to remove this note from this entity?')}
      />

      <DeleteDialog
        deletion={noteDeletion}
        submitDelete={submitNoteDelete}
        message={t_i18n('Do you want to delete this note?')}
      />

      <QueryRenderer
        query={noteEditionQuery}
        variables={{ id: note.id }}
        render={({ props }: { props: NoteEditionContainerQuery$data }) => {
          if (props && props.note) {
            return (
              <NoteEditionContainer
                note={props.note}
                handleClose={() => setDisplayEdit(false)}
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
