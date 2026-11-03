import { Icon, type IconName, Text } from '@filigran/design-system';
import type { ReactNode } from 'react';
import './emptyState.css';

export const EmptyState = ({ icon, title, children }: { icon: IconName; title: string; children?: ReactNode }) => (
  <div className="sv-empty">
    <Icon name={icon} size={24} className="sv-faint" />
    <Text variant="title-xs">{title}</Text>
    {children && <div className="sv-empty__body">{children}</div>}
  </div>
);
