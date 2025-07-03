import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { RelayError } from '../../../../relay/relayTypes';
import { MESSAGING$ } from '../../../../relay/environment';
import DeleteDialog from '../../../../components/DeleteDialog';

const securityPlatformDeletionMutation = graphql`
mutation SecurityPlatformDeletionMutation($id: ID!) {
    securityPlatformDelete(id: $id)
}
`;

const SecurityPlatformDeletion = ({ id, isOpen, handleClose }: { id: string, isOpen: boolean, handleClose: () => void }) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const deletion = useDeletion({ handleClose });
  const { setDeleting } = deletion;

  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: ('entity_SecurityPlatform') },
  });

  const [commit] = useApiMutation(
    securityPlatformDeletionMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id,
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/entities/security_platforms');
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
      message={t_i18n('Do you want to delete this security platform?')}
    />
  );
};

export default SecurityPlatformDeletion;
