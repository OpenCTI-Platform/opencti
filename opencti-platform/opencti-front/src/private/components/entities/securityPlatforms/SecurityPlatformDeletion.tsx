import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import Button from '@mui/material/Button';
import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { RelayError } from '../../../../relay/relayTypes';
import { MESSAGING$ } from '../../../../relay/environment';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import DeleteDialog from '../../../../components/DeleteDialog';

const securityPlatformDeletionMutation = graphql`
mutation SecurityPlatformDeletionMutation($id: ID!) {
    securityPlatformDelete(id: $id)
}
`;

const SecurityPlatformDeletion = ({ id }: { id: string }) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const handleClose = () => {};
  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete, deleting } = deletion;

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
        message={t_i18n('Do you want to delete this security platform?')}
      />
    </>
  );
};

export default SecurityPlatformDeletion;
