import React from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { RelayError } from '../../../../relay/relayTypes';
import { MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';

const ThreatActorIndividualDeletionDeleteMutation = graphql`
  mutation ThreatActorIndividualDeletionDeleteMutation($id: ID!) {
    threatActorIndividualDelete(id: $id)
  }
`;

const ThreatActorIndividualDeletion = ({ id, isOpen, handleClose }: { id: string, isOpen: boolean, handleClose: () => void }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Threat-Actor-Individual') },
  });
  const [commit] = useApiMutation(
    ThreatActorIndividualDeletionDeleteMutation,
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
        navigate('/dashboard/threats/threat_actors_individual');
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
      message={t_i18n('Do you want to delete this threat actor individual?')}
    />
  );
};

export default ThreatActorIndividualDeletion;
