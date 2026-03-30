import React from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';
import useDeletion from '../../../../utils/hooks/useDeletion';

const RegionDeletionDeleteMutation = graphql`
  mutation RegionDeletionDeleteMutation($id: ID!) {
    regionEdit(id: $id) {
      delete
    }
  }
`;

const RegionDeletion = ({ id, isOpen, handleClose }: { id: string; isOpen: boolean; handleClose: () => void }) => {
  const { t_i18n } = useFormatter();
  const { translateEntityType } = useEntityTranslation();
  const navigate = useNavigate();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: translateEntityType('Region') },
  });
  const [commit] = useApiMutation(
    RegionDeletionDeleteMutation,
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
        navigate('/dashboard/locations/regions');
      },
    });
  };

  return (
    <DeleteDialog
      deletion={deletion}
      submitDelete={submitDelete}
      isOpen={isOpen}
      onClose={handleClose}
      message={t_i18n('Do you want to delete this') + ' ' + translateEntityType('Region') + '?'}
    />
  );
};

export default RegionDeletion;
