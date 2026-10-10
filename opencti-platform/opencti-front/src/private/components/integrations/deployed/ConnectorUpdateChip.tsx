import React from 'react';
import { Chip, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';

interface ConnectorUpdateChipProps {
  // Version to install
  version?: string | null;
  // Shows the version in the label, where there is room for it, instead of the tooltip
  versionInLabel?: boolean;
  // A version even newer than the update exists, but it is not compatible with this platform
  hasNewerIncompatibleVersion?: boolean;
}

// The connector has an update it can install: the newer incompatible version is only a hint,
// it never replaces the label (the deployed connector itself is not incompatible).
const ConnectorUpdateChip: React.FC<ConnectorUpdateChipProps> = ({ version, versionInLabel = false, hasNewerIncompatibleVersion = false }) => {
  const { t_i18n } = useFormatter();
  const label = versionInLabel && version ? `${t_i18n('Update available')}: ${version}` : t_i18n('Update available');
  const hints = [
    !versionInLabel && version ? t_i18n('Version {version} can be installed', { values: { version } }) : null,
    hasNewerIncompatibleVersion ? t_i18n('A newer version is not compatible with this platform') : null,
  ].filter((hint): hint is string => hint !== null);
  const chip = <Chip severity="info" label={label} />;
  if (hints.length === 0) {
    return chip;
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex" tabIndex={0}>
          {chip}
        </span>
      </TooltipTrigger>
      <TooltipContent>
        {hints.map((hint) => <div key={hint}>{hint}</div>)}
      </TooltipContent>
    </Tooltip>
  );
};

export default ConnectorUpdateChip;
