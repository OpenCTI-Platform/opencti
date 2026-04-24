import { type FormikConfig } from 'formik';
import { useNavigate } from 'react-router-dom';
import Drawer from '@components/common/drawer/Drawer';
import useCustomViewAdd from './useCustomViewAdd';
import CustomViewForm, { type CustomViewFormInputs } from './CustomViewForm';
import { useFormatter } from '../../../../../components/i18n';
import { handleError, MESSAGING$ } from '../../../../../relay/environment';

interface CustomViewFormDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  entityType: string;
}

const CustomViewFormDrawer = ({
  isOpen,
  onClose,
  entityType,
}: CustomViewFormDrawerProps) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const createTitle = t_i18n('Create custom view');

  const [commitAddMutation] = useCustomViewAdd();

  const onAdd: FormikConfig<CustomViewFormInputs>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    commitAddMutation({
      variables: {
        input: {
          name: values.name,
          description: values.description,
          targetEntityType: entityType,
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

  return (
    <>
      <Drawer
        title={createTitle}
        open={isOpen}
        onClose={onClose}
      >
        <CustomViewForm
          onClose={onClose}
          onSubmit={onAdd}
        />
      </Drawer>
    </>
  );
};

export default CustomViewFormDrawer;
