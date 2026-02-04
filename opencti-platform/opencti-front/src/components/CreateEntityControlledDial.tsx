import Button, { ButtonVariant } from '@common/button/Button';
import React, { FunctionComponent } from 'react';
import { DrawerControlledDialProps } from '../private/components/common/drawer/Drawer';
import { useGetCurrentUserAccessRight } from '../utils/authorizedMembers';
import useDraftContext from '../utils/hooks/useDraftContext';
import { ButtonSize } from './common/button/Button.types';
import { useFormatter } from './i18n';

interface CreateEntityControlledDialProps extends DrawerControlledDialProps {
  entityType: string;
  size?: ButtonSize;
  variant?: ButtonVariant;// 'text' | 'contained' | 'outlined';
  style?: React.CSSProperties;
}

const CreateEntityControlledDial: FunctionComponent<CreateEntityControlledDialProps> = ({
  onOpen,
  entityType,
  size = 'default',
  variant = 'primary',
}) => {
  const { t_i18n } = useFormatter();
  const valueString = entityType ? t_i18n(`entity_${entityType}`) : t_i18n('Entity');
  const buttonValue = t_i18n('', {
    id: 'Create ...',
    values: { entity_type: valueString },
  });
  // Remove create button in Draft context without the minimal right access "canEdit"
  const draftContext = useDraftContext();
  const currentAccessRight = useGetCurrentUserAccessRight(draftContext?.currentUserAccessRight);
  const canDisplayButton = !draftContext || currentAccessRight.canEdit;

  if (!canDisplayButton) return null;

  return (
    <Button
      onClick={onOpen}
      size={size}
      variant={variant}
      aria-label={buttonValue}
      title={buttonValue}
      data-testid={`create-${entityType.toLowerCase()}-button`}
    >
      {buttonValue}
    </Button>
  );
};

export default CreateEntityControlledDial;
