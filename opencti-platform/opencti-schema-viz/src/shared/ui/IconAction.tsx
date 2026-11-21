import { Icon, IconButton, type IconButtonProps, type IconName, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { forwardRef } from 'react';

interface IconActionProps extends Omit<IconButtonProps, 'icon' | 'aria-label'> {
  icon: IconName;
  label: string;
}

export const IconAction = forwardRef<HTMLButtonElement, IconActionProps>(({ icon, label, size = 'sm', priority = 'tertiary', ...props }, ref) => (
  <Tooltip>
    <TooltipTrigger asChild>
      <IconButton ref={ref} icon={<Icon name={icon} size={16} />} aria-label={label} size={size} priority={priority} {...props} />
    </TooltipTrigger>
    <TooltipContent>{label}</TooltipContent>
  </Tooltip>
));
