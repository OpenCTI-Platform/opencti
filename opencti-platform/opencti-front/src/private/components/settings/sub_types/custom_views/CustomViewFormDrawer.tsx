import { type FormikConfig } from 'formik';
import { useNavigate } from 'react-router-dom';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../../components/i18n';
import { handleError, MESSAGING$ } from '../../../../../relay/environment';
import useCustomViewEdit from './useCustomViewEdit';
import useCustomViewAdd from './useCustomViewAdd';
import CustomViewForm, { type CustomViewFormInputs } from './CustomViewForm';

interface CustomViewFormDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  entityType: string;
  customView?: { id: string } & CustomViewFormInputs;
}

const CustomViewFormDrawer = ({
  isOpen,
  onClose,
  entityType,
  customView,
}: CustomViewFormDrawerProps) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const createTitle = t_i18n('Create custom view');
  const editionTitle = t_i18n('Update custom view');
  const isEdition = !!customView;

  const commitAddMutation = useCustomViewAdd();
  const [commitEditMutation] = useCustomViewEdit();

  const handleSubmitForm: FormikConfig<CustomViewFormInputs>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    if (isEdition) return;
    commitAddMutation({
      variables: {
        input: {
          name: values.name,
          description: values.description,
          targetEntityType: entityType,
          enabled: values.enabled,
        },
      },
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        onClose();
        if (response.customViewAdd) {
          const { id } = response.customViewAdd;
          MESSAGING$.notifySuccess(t_i18n('Custom view created'));
          navigate(`/dashboard/settings/customization/entity_types/${entityType}/custom-views/${id}`);
        }
      },
      onError: (error) => {
        setSubmitting(false);
        handleError(error);
      },
    });
  };

  const handleEditField = (field: string, value: unknown) => {
    if (!isEdition) return;
    const input: { key: string; value: [unknown] } = { key: field, value: [value] };
    commitEditMutation({
      variables: { id: customView.id, input: [input] },
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('Custom view updated'));
      },
      onError: () => {
        MESSAGING$.notifyError(t_i18n('Failed to update custom view'));
      },
    });
  };

  const title = isEdition ? editionTitle : createTitle;

  return (
    <Drawer
      title={title}
      open={isOpen}
      onClose={onClose}
    >
      <CustomViewForm
        onClose={onClose}
        onSubmit={handleSubmitForm}
        onSubmitField={handleEditField}
        isEdition={isEdition}
        values={customView}
      />
    </Drawer>
  );
};

export default CustomViewFormDrawer;
