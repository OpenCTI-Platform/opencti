import React, { FunctionComponent } from 'react';
import { useNavigate } from 'react-router-dom';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { MESSAGING$ } from '../../../../relay/environment';
import { RelayError } from '../../../../relay/relayTypes';

const GroupingDeletionDeleteMutation = graphql`
  mutation GroupingDeletionDeleteMutation($id: ID!) {
    groupingDelete(id: $id)
  }
`;

interface GroupingDeletionProps {
  groupingId: string;
  handleClose?: () => void;
  isOpen: boolean
}

const GroupingDeletion: FunctionComponent<GroupingDeletionProps> = ({
  groupingId,
  handleClose,
  isOpen,
}) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Grouping') },
  });
  const [commitMutation] = useApiMutation(
    GroupingDeletionDeleteMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );
  const deletion = useDeletion({ handleClose });
  const { setDeleting } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      variables: { id: groupingId },
      onCompleted: () => {
        setDeleting(false);
        navigate('/dashboard/analyses/groupings');
      },
      onError: (error) => {
        MESSAGING$.notifyRelayError(error as unknown as RelayError);
      },
    });
  };

  return (
    <>
      <DeleteDialog
        deletion={deletion}
        isOpen={isOpen}
        onClose={handleClose}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this grouping?')}
      />
    </>
  );
};

export default GroupingDeletion;
