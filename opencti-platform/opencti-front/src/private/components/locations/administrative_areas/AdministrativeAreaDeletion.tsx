import React from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import useDeletion from '../../../../utils/hooks/useDeletion';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';
import { useEntityTypeDisplayName } from '../../../../utils/hooks/useEntityTypeDisplayName';

const AdministrativeAreaDeletionDeleteMutation = graphql`
  mutation AdministrativeAreaDeletionDeleteMutation($id: ID!) {
    administrativeAreaDelete(id: $id)
  }
`;

const AdministrativeAreaDeletion = ({ id, isOpen, handleClose }: { id: string; isOpen: boolean; handleClose: () => void }) => {
  const { t_i18n } = useFormatter();
  const entityTypeDisplayName = useEntityTypeDisplayName();
  const navigate = useNavigate();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: entityTypeDisplayName('Administrative-Area') },
  });
  const [commit] = useApiMutation(
    AdministrativeAreaDeletionDeleteMutation,
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
        navigate('/dashboard/locations/administrative_areas');
      },
    });
  };
  return (
    <DeleteDialog
      deletion={deletion}
      submitDelete={submitDelete}
      isOpen={isOpen}
      onClose={handleClose}
      message={t_i18n('Do you want to delete this area?')}
    />
  );
};

export default AdministrativeAreaDeletion;
