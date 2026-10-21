import React from 'react';
import { AutoFixHighOutlined, BusinessOutlined, HubOutlined, PersonOutlined, RssFeedOutlined, ScienceOutlined, HelpOutlineOutlined } from '@mui/icons-material';
import type { SvgIconProps } from '@mui/material/SvgIcon';

const ICONS: Record<string, React.ComponentType<SvgIconProps>> = {
  connector: HubOutlined,
  feed: RssFeedOutlined,
  author: BusinessOutlined,
  user: PersonOutlined,
  inference: AutoFixHighOutlined,
  emulation: ScienceOutlined,
};

const ProvenanceSourceKindIcon = ({ kind, ...props }: { kind: string | null | undefined } & SvgIconProps) => {
  const Icon = ICONS[kind ?? ''] ?? HelpOutlineOutlined;
  return <Icon fontSize="small" {...props} />;
};

export default ProvenanceSourceKindIcon;
