import React from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { RelayError } from '../../../../relay/relayTypes';
import { MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';

const CaseIncidentDeletionDeleteMutation = graphql`
  mutation CaseIncidentDeletionDeleteMutation($id: ID!) {
    caseIncidentDelete(id: $id)
  }
`;

const CaseIncidentDeletion = ({ id, isOpen, handleClose }: { id: string, isOpen: boolean, handleClose: () => void }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Case-Incident') },
  });
  const [commit] = useApiMutation(
    CaseIncidentDeletionDeleteMutation,
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
        navigate('/dashboard/cases/incidents');
      },
      onError: (error) => {
        MESSAGING$.notifyRelayError(error as unknown as RelayError);
      },
    });
  };
  return (
    <DeleteDialog
      deletion={deletion}
      isOpen={isOpen}
      onClose={handleClose}
      submitDelete={submitDelete}
      message={t_i18n('Do you want to delete this incident response?')}
    />
  );
};

export default CaseIncidentDeletion;
