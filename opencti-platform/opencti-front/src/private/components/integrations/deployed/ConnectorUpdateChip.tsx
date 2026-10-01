import React from 'react';
import { Chip, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';

interface ConnectorUpdateChipProps {
  // Version to install, shown in the label when given
  version?: string | null;
  // A version even newer than the update exists, but it needs a newer platform
  incompatibility?: boolean;
}

// The connector has an update it can install: the newer incompatible version is only a hint,
// it never replaces the label (the deployed connector itself is not incompatible).
const ConnectorUpdateChip: React.FC<ConnectorUpdateChipProps> = ({ version, incompatibility = false }) => {
  const { t_i18n } = useFormatter();
  const label = version ? `${t_i18n('Update available')}: ${version}` : t_i18n('Update available');
  const chip = <Chip severity="info" label={label} />;
  if (!incompatibility) {
    return chip;
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex" tabIndex={0}>
          {chip}
        </span>
      </TooltipTrigger>
      <TooltipContent>{t_i18n('A newer version needs a platform upgrade')}</TooltipContent>
    </Tooltip>
  );
};

export default ConnectorUpdateChip;
