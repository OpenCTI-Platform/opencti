import React from 'react';
import { useNavigate } from 'react-router';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { MESSAGING$ } from '../../../../relay/environment';
import { RelayError } from '../../../../relay/relayTypes';
import DeleteDialog from '../../../../components/DeleteDialog';

const DataComponentDeletionDeleteMutation = graphql`
  mutation DataComponentDeletionDeleteMutation($id: ID!) {
    dataComponentDelete(id: $id)
  }
`;

const DataComponentDeletion = ({ id, isOpen, handleClose }: { id: string, isOpen: boolean, handleClose: () => void }) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Data-Component') },
  });
  const [commit] = useApiMutation(
    DataComponentDeletionDeleteMutation,
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
        navigate('/dashboard/techniques/data_components');
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
      submitDelete={submitDelete}
      isOpen={isOpen}
      onClose={handleClose}
      message={t_i18n('Do you want to delete this data component?')}
    />
  );
};

export default DataComponentDeletion;
