import { graphql } from 'react-relay';
import React from 'react';
import { useNavigate } from 'react-router-dom';
import Button from '@mui/material/Button';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../utils/hooks/useDeletion';
import DeleteDialog from '../../../../components/DeleteDialog';
import { MESSAGING$ } from '../../../../relay/environment';
import { RelayError } from '../../../../relay/relayTypes';

const fintelDesignDeletionMutation = graphql`
  mutation FintelDesignDeletionMutation($id: ID!) {
    fintelDesignDelete(id: $id)
  }
`;

const FintelDesignDeletion = ({
  id,
}: { id: string }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_FintelDesign') },
  });

  const [commitDelete] = useApiMutation(
    fintelDesignDeletionMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  // delete
  const deletion = useDeletion({});
  const { setDeleting, handleOpenDelete, deleting } = deletion;
  const submitDelete = () => {
    commitDelete({
      variables: {
        id,
      },
      onCompleted: () => {
        setDeleting(false);
        navigate('/dashboard/settings/customization/fintel_designs');
      },
      onError: (error) => {
        const { errors } = (error as unknown as RelayError).res;
        MESSAGING$.notifyError(errors.at(0)?.message);
      },
    });
  };

  return (
    <>
      <Button
        color="error"
        variant="contained"
        onClick={handleOpenDelete}
        disabled={deleting}
        sx={{ marginTop: 2 }}
      >
        {t_i18n('Delete')}
      </Button>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this fintel design?')}
      />
    </>
  );
};

export default FintelDesignDeletion;
