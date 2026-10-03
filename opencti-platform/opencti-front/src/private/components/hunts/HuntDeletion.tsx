import React from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router';
import { useFormatter } from '../../../components/i18n';
import DeleteDialog from '../../../components/DeleteDialog';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useDeletion from '../../../utils/hooks/useDeletion';
import { PATH_HUNTS } from '../common/routes/paths';

const huntDeletionMutation = graphql`
  mutation HuntDeletionDeleteMutation($id: ID!) {
    huntDelete(id: $id)
  }
`;

interface HuntDeletionProps {
  huntId: string;
  isOpen: boolean;
  handleClose: () => void;
}

const HuntDeletion = ({ huntId, isOpen, handleClose }: HuntDeletionProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [commit] = useApiMutation(huntDeletionMutation);
  const deletion = useDeletion({ handleClose });
  const { setDeleting } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: { id: huntId },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate(PATH_HUNTS);
      },
      onError: () => setDeleting(false),
    });
  };
  return (
    <DeleteDialog
      deletion={deletion}
      submitDelete={submitDelete}
      isOpen={isOpen}
      onClose={handleClose}
      message={t_i18n('Do you want to delete this hunt?')}
    />
  );
};

export default HuntDeletion;
