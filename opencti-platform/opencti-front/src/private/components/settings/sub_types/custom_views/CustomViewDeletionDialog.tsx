import { type UIEvent } from 'react';
import { graphql } from 'relay-runtime';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import DeleteDialog from '../../../../../components/DeleteDialog';
import { useCustomViewsData } from '../../../../components/custom_views/useCustomViewsData';
import { CustomViewDeletionDialog_Mutation } from './__generated__/CustomViewDeletionDialog_Mutation.graphql';
import stopEvent from '../../../../../utils/domEvent';
import { deleteNode } from '../../../../../utils/store';

const customViewDeletionDialogMutation = graphql`
    mutation CustomViewDeletionDialog_Mutation($id: ID!) {
        customViewDelete(id: $id)
    }
`;

interface CustomViewDeletionDialogProps {
  id: string;
  isOpen: boolean;
  handleClose: (e?: UIEvent) => void;
  onDeleted?: () => void;
  paginationOptions?: Record<string, unknown>;
}

const CustomViewDeletionDialog = ({
  id,
  isOpen,
  handleClose,
  onDeleted,
  paginationOptions,
}: CustomViewDeletionDialogProps) => {
  const { t_i18n } = useFormatter();
  const { refetchCustomViews } = useCustomViewsData();
  const deleteSuccessMessage = t_i18n('Custom view successfully deleted');

  const [commit] = useApiMutation<CustomViewDeletionDialog_Mutation>(
    customViewDeletionDialogMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  const deletion = useDeletion({ handleClose });
  const { setDeleting } = deletion;

  const submitDelete = (e: UIEvent) => {
    stopEvent(e);
    setDeleting(true);
    commit({
      variables: {
        id,
      },
      updater: (store) => {
        if (paginationOptions) {
          deleteNode(store, 'CustomViewsSettingsDataTable_customViews', paginationOptions, id);
        }
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        refetchCustomViews();
        onDeleted?.();
      },
    });
  };
  return (
    <DeleteDialog
      deletion={deletion}
      submitDelete={submitDelete}
      isOpen={isOpen}
      onClose={handleClose}
      message={t_i18n('Do you want to delete this custom view?')}
    />
  );
};

export default CustomViewDeletionDialog;
