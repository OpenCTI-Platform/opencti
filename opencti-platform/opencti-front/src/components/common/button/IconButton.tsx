import React from 'react';
import Button, { CustomButtonProps } from './Button';

const IconButton: React.FC<Omit<CustomButtonProps, 'iconOnly'>> = (props) => {
  return (
    <Button
      variant="tertiary"
      size="small"
      {...(props as CustomButtonProps)}
      iconOnly
    />
  );
};

export default IconButton;
