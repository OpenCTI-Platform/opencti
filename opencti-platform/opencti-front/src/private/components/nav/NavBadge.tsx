import { Badge, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import React from 'react';
import { NavItemBadge } from './useNavMenu';

interface NavBadgeProps {
  badge: NavItemBadge;
  // The collapsed rail has only room for a dot
  compact: boolean;
}

const NavBadge: React.FC<NavBadgeProps> = ({ badge, compact }) => (
  <Tooltip>
    <TooltipTrigger asChild>
      <span className="inline-flex" aria-hidden="true">
        <Badge
          bareAnchor={compact ? false : 'md'}
          content={badge.content}
          dot={compact}
          accessibleText={badge.accessibleText}
        >
          <span className="inline-flex h-4 w-4 shrink-0" aria-hidden="true" />
        </Badge>
      </span>
    </TooltipTrigger>
    <TooltipContent side="right">{badge.accessibleText}</TooltipContent>
  </Tooltip>
);

export default NavBadge;
