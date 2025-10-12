import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { deleteNode } from '../../../../utils/store';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../utils/hooks/useDeletion';
import DeleteDialog from '../../../../components/DeleteDialog';

const securityCoverageDeletionMutation = graphql`
  mutation SecurityCoverageDeletionDeleteMutation($id: ID!) {
    securityCoverageDelete(id: $id)
  }
`;

interface SecurityCoverageDeletionProps {
  id: string;
  isOpen: boolean;
  handleClose: () => void;
  objectPath?: string;
}

const SecurityCoverageDeletion: FunctionComponent<SecurityCoverageDeletionProps> = ({
  id,
  isOpen,
  handleClose,
  objectPath = '/dashboard/analyses/security_coverages',
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [commitMutation] = useApiMutation(securityCoverageDeletionMutation);
  const deletion = useDeletion({ handleClose });
  const { setDeleting } = deletion;

  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      variables: {
        id,
      },
      updater: (store) => {
        deleteNode(
          store,
          'Pagination__securityCoverages',
          {},
          id,
        );
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        if (window.location.pathname.includes(id)) {
          navigate(objectPath);
        }
      },
    });
  };

  return (
    <DeleteDialog
      deletion={deletion}
      submitDelete={submitDelete}
      isOpen={isOpen}
      onClose={handleClose}
      message={t_i18n('Do you want to delete this security coverage?')}
    />
  );
};

export default SecurityCoverageDeletion;
