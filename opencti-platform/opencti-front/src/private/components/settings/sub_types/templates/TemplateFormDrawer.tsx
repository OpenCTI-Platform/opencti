import Drawer from '@components/common/drawer/Drawer';
import React from 'react';
import TemplateForm, { TemplateFormInputs } from '@components/settings/sub_types/templates/TemplateForm';
import { useFormatter } from '../../../../../components/i18n';

interface TemplateFormDrawerProps {
  isOpen: boolean
  onClose: () => void
  template?: TemplateFormInputs
}

const TemplateFormDrawer = ({
  isOpen,
  onClose,
  template,
}: TemplateFormDrawerProps) => {
  const { t_i18n } = useFormatter();
  const createTitle = t_i18n('Create a template');
  const editionTitle = t_i18n('Update a template');

  return (
    <Drawer
      title={template ? editionTitle : createTitle}
      open={isOpen}
      onClose={onClose}
    >
      <TemplateForm
        onClose={onClose}
        onSubmit={console.log}
        onSubmitField={console.log}
        isEdition={!!template}
        defaultValues={template}
      />
    </Drawer>
  );
};

export default TemplateFormDrawer;
