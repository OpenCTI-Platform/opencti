import React from 'react';
import Button, { CustomButtonProps } from './Button';

const IconButton: React.FC<Omit<CustomButtonProps, 'iconOnly'>> = (props) => {
  return (
    <Button
      {...(props as CustomButtonProps)}
      iconOnly
      variant="tertiary"
      size="small"
    />
  );
};

export default IconButton;
