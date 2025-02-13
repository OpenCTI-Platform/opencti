import React, { FunctionComponent } from 'react';
import { useNavigate } from 'react-router-dom';
import Button from '@mui/material/Button';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

const GroupingDeletionDeleteMutation = graphql`
  mutation GroupingDeletionDeleteMutation($id: ID!) {
    groupingDelete(id: $id)
  }
`;

interface GroupingDeletionProps {
  groupingId: string;
  handleClose?: () => void;
}

const GroupingDeletion: FunctionComponent<GroupingDeletionProps> = ({
  groupingId,
  handleClose,
}) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Grouping') },
  });
  const [commitMutation] = useApiMutation(
    GroupingDeletionDeleteMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );
  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete, deleting } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      variables: { id: groupingId },
      onCompleted: () => {
        setDeleting(false);
        if (typeof handleClose === 'function') handleClose();
        navigate('/dashboard/analyses/groupings');
      },
    });
  };

  return (
    <>
      <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
        <Button
          color="error"
          variant="contained"
          onClick={handleOpenDelete}
          disabled={deleting}
          sx={{ marginTop: 2 }}
        >
          {t_i18n('Delete')}
        </Button>
      </Security>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this grouping?')}
      />
    </>
  );
};

export default GroupingDeletion;
