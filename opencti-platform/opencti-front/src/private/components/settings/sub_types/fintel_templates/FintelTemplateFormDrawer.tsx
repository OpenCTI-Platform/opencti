import Drawer from '@components/common/drawer/Drawer';
import React from 'react';
import FintelTemplateForm, { FintelTemplateFormInputs } from './FintelTemplateForm';
import { useFormatter } from '../../../../../components/i18n';

interface FintelTemplateFormDrawerProps {
  isOpen: boolean
  onClose: () => void
  template?: FintelTemplateFormInputs
}

const FintelTemplateFormDrawer = ({
  isOpen,
  onClose,
  template,
}: FintelTemplateFormDrawerProps) => {
  const { t_i18n } = useFormatter();
  const createTitle = t_i18n('Create a template');
  const editionTitle = t_i18n('Update a template');

  return (
    <Drawer
      title={template ? editionTitle : createTitle}
      open={isOpen}
      onClose={onClose}
    >
      <FintelTemplateForm
        onClose={onClose}
        onSubmit={console.log}
        onSubmitField={console.log}
        isEdition={!!template}
        defaultValues={template}
      />
    </Drawer>
  );
};

export default FintelTemplateFormDrawer;
