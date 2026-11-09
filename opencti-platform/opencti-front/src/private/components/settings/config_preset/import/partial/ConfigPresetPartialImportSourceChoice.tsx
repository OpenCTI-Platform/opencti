import React, { FunctionComponent, ReactNode } from 'react';
import { DescriptionOutlined, FolderZipOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import Card from '@common/card/Card';
import { Text } from '@filigran/design-system';
import { useFormatter } from '../../../../../../components/i18n';
import type { Theme } from '../../../../../../components/Theme';

export type ConfigPresetPartialImportSource = 'file' | 'bundle';

interface ConfigPresetPartialImportSourceChoiceProps {
  // null until the user chooses
  value: ConfigPresetPartialImportSource | null;
  onChange: (source: ConfigPresetPartialImportSource) => void;
  // The import the screen already had, already translated (a theme file...)
  fileLabel: string;
  fileDescription: string;
  // What the bundle import takes from the bundle, already translated
  bundleDescription: string;
  disabled?: boolean;
}

interface SourceCardProps {
  icon: ReactNode;
  label: string;
  description: string;
  selected: boolean;
  disabled?: boolean;
  testId: string;
  onClick: () => void;
}

const SourceCard: FunctionComponent<SourceCardProps> = ({ icon, label, description, selected, disabled, testId, onClick }) => {
  const theme = useTheme<Theme>();
  return (
    <div data-testid={testId}>
      <Card selected={selected} disabled={disabled} onClick={onClick} aria-label={label}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1) }}>
          {icon}
          <Text variant="title-sm">{label}</Text>
          <Text variant="content-base" style={{ color: theme.palette.text.secondary }}>{description}</Text>
        </div>
      </Card>
    </div>
  );
};

// The choice of a screen that imports its items: the import it already had, or the items of its type taken from a configuration bundle.
// Two cards side by side, the chosen one highlighted. Generic: any screen that offers the partial import shows it.
const ConfigPresetPartialImportSourceChoice: FunctionComponent<ConfigPresetPartialImportSourceChoiceProps> = ({
  value,
  onChange,
  fileLabel,
  fileDescription,
  bundleDescription,
  disabled,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5) }}>
      <Text variant="title-sm">{t_i18n('Choose the import method')}</Text>
      <Text variant="content-base">{t_i18n('Select one of the two options below, then click Next.')}</Text>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: theme.spacing(2) }}>
        <SourceCard
          icon={<DescriptionOutlined fontSize="small" aria-hidden />}
          label={fileLabel}
          description={fileDescription}
          selected={value === 'file'}
          disabled={disabled}
          testId="import-source-file"
          onClick={() => onChange('file')}
        />
        <SourceCard
          icon={<FolderZipOutlined fontSize="small" aria-hidden />}
          label={t_i18n('Import from bundle platform config')}
          description={bundleDescription}
          selected={value === 'bundle'}
          disabled={disabled}
          testId="import-source-bundle"
          onClick={() => onChange('bundle')}
        />
      </div>
    </div>
  );
};

export default ConfigPresetPartialImportSourceChoice;
