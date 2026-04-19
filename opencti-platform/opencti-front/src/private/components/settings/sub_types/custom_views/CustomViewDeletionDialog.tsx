import { useNavigate } from 'react-router-dom';
import { graphql } from 'relay-runtime';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import DeleteDialog from '../../../../../components/DeleteDialog';
import { useCustomViewsData } from '../../../../components/custom_views/useCustomViewsData';
import useEntityTranslation from '../../../../../utils/hooks/useEntityTranslation';
import { CustomViewDeletionDialog_Mutation } from './__generated__/CustomViewDeletionDialog_Mutation.graphql';

const customViewDeletionDialogMutation = graphql`
    mutation CustomViewDeletionDialog_Mutation($id: ID!) {
        customViewDelete(id: $id)
    }
`;

interface CustomViewDeletionDialogProps {
  id: string;
  isOpen: boolean;
  handleClose: () => void;
  targetEntityType: string;
}

const CustomViewDeletionDialog = ({
  id,
  isOpen,
  handleClose,
  targetEntityType,
}: CustomViewDeletionDialogProps) => {
  const { translateEntityType } = useEntityTranslation();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const { refetchCustomViews } = useCustomViewsData();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: translateEntityType('CustomView') },
  });

  const [commit] = useApiMutation<CustomViewDeletionDialog_Mutation>(
    customViewDeletionDialogMutation,
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
        refetchCustomViews();
        navigate(`/dashboard/settings/customization/entity_types/${targetEntityType}/custom-views`);
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
