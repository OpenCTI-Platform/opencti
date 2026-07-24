import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FintelDesignsLinesPaginationQuery$variables } from '@components/settings/fintel_design/__generated__/FintelDesignsLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../utils/hooks/useDeletion';
import DeleteDialog from '../../../../components/DeleteDialog';
import { MESSAGING$ } from '../../../../relay/environment';
import { RelayError } from '../../../../relay/relayTypes';
import { deleteNode } from '../../../../utils/store';

const fintelDesignDeletionMutation = graphql`
  mutation FintelDesignDeletionMutation($id: ID!) {
    fintelDesignDelete(id: $id)
  }
`;

const FintelDesignDeletion = ({
  id,
  isOpen,
  handleClose,
  paginationOptions,
  onDeleteComplete,
}: {
  id: string;
  isOpen: boolean;
  handleClose: () => void;
  paginationOptions?: FintelDesignsLinesPaginationQuery$variables;
  onDeleteComplete?: () => void;
}) => {
  const { t_i18n } = useFormatter();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_FintelDesign') },
  });

  const [commitDelete] = useApiMutation(
    fintelDesignDeletionMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  // delete
  const deletion = useDeletion({});
  const { setDeleting } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commitDelete({
      variables: {
        id,
      },
      updater: paginationOptions
        ? (store: RecordSourceSelectorProxy) => deleteNode(
            store,
            'Pagination_fintelDesigns',
            paginationOptions,
            id,
          )
        : undefined,
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        onDeleteComplete?.();
      },
      onError: (error) => {
        setDeleting(false);
        handleClose();
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
      message={t_i18n('Do you want to delete this fintel design?')}
    />
  );
};

export default FintelDesignDeletion;
