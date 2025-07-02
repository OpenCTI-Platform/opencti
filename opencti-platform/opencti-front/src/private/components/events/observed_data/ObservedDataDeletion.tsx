import React from 'react';
import { useNavigate } from 'react-router-dom';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { MESSAGING$ } from '../../../../relay/environment';
import { RelayError } from '../../../../relay/relayTypes';
import DeleteDialog from '../../../../components/DeleteDialog';

const ObservedDataDeletionDeleteMutation = graphql`
  mutation ObservedDataDeletionDeleteMutation($id: ID!) {
    observedDataEdit(id: $id) {
        delete
      }
    }
  `;

const ObservedDataDeletion = ({ id, isOpen, handleClose }: { id: string, isOpen: boolean, handleClose: () => void }) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Observed-Data') },
  });
  const [commit] = useApiMutation(
    ObservedDataDeletionDeleteMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );
  const deletion = useDeletion({ handleClose });
  const { setDeleting } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id,
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/events/observed_data');
      },
      onError: (error) => {
        const { errors } = (error as unknown as RelayError).res;
        MESSAGING$.notifyError(errors.at(0)?.message);
      },
    });
  };
  return (
    <DeleteDialog
      deletion={deletion}
      isOpen={isOpen}
      onClose={handleClose}
      submitDelete={submitDelete}
      message={t_i18n('Do you want to delete this observed data?')}
    />
  );
};

export default ObservedDataDeletion;
