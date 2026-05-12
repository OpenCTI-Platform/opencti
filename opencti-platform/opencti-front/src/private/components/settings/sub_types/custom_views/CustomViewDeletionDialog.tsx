import { type UIEvent } from 'react';
import { graphql } from 'relay-runtime';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { Deletion } from '../../../../../utils/hooks/useDeletion';
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
  deletion: Deletion;
  onDeleted?: () => void;
  paginationOptions?: Record<string, unknown>;
}

const CustomViewDeletionDialog = ({
  id,
  deletion,
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

  const submitDelete = (e: UIEvent) => {
    stopEvent(e);
    deletion.setDeleting(true);
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
        deletion.setDeleting(false);
        refetchCustomViews();
        onDeleted?.();
      },
    });
  };
  return (
    <DeleteDialog
      deletion={deletion}
      submitDelete={submitDelete}
      message={t_i18n('Do you want to delete this custom view?')}
    />
  );
};

export default CustomViewDeletionDialog;
