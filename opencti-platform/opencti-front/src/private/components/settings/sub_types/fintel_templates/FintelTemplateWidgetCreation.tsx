import Drawer from '@components/common/drawer/Drawer';
import React, { FunctionComponent } from 'react';
import { useFormatter } from '../../../../../components/i18n';

interface FintelTemplateWidgetCreationProps {
  onClose: () => void,
  isOpen: boolean,
}

const FintelTemplateWidgetCreation: FunctionComponent<FintelTemplateWidgetCreationProps> = ({ onClose, isOpen }) => {
  const { t_i18n } = useFormatter();
  return (
    <Drawer
      title={t_i18n('Create a widget')}
      open={isOpen}
      onClose={onClose}
    >
    </Drawer>
  );
};

export default FintelTemplateWidgetCreation;
