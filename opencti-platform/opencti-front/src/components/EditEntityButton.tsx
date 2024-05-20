import React from 'react';
import { Button, styled } from '@mui/material';
import { Edit } from '@mui/icons-material';
import { useFormatter } from './i18n';

interface EditEntityControlledDialOptions {
  size?: 'small' | 'medium' | 'large'
  variant?: 'text' | 'contained' | 'outlined'
  margin?: string
}

/**
 * Get a generator for an entity edit button
 * @param opts.size size of the button and its icon
 * @param opts.variant type of button
 * @param opts.margin css margin. defaults to 3px on left
 * @returns Generator that takes an onOpen function and returns a button
 */
function EditEntityControlledDial({
  size = 'small',
  variant = 'contained',
  margin = '0 0 0 3px',
}: EditEntityControlledDialOptions = {}) {
  const EditEntityButton = ({ onOpen }: { onOpen: () => void }) => {
    const { t_i18n } = useFormatter();
    const buttonLabel = t_i18n('Edit');
    const StyledEditButton = styled(Button)({
      margin,
    });
    return (
      <StyledEditButton
        onClick={onOpen}
        variant={variant}
        size={size}
        aria-label={buttonLabel}
      >
        {buttonLabel} <Edit fontSize={size} />
      </StyledEditButton>
    );
  };
  return EditEntityButton;
}

export default EditEntityControlledDial;
