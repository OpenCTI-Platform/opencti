import React from 'react';
import Button from '@mui/material/Button';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { handleError } from '../../../../relay/environment';

const DecayRuleDeletionDeleteMutation = graphql`
  mutation DecayRuleDeletionDeleteMutation($id: ID!) {
    decayRuleDelete(id: $id)
  }
`;

const DecayRuleDeletion = ({ id }: { id: string }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_DecayRule') },
  });
  const [commit] = useApiMutation(
    DecayRuleDeletionDeleteMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );
  const handleClose = () => {};
  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete, deleting } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id,
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/settings/customization/decay/');
      },
      onError: (error: Error) => {
        handleError(error);
        handleClose();
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
        message={t_i18n('Do you want to delete this decay rule?')}
      />
    </>
  );
};

export default DecayRuleDeletion;
