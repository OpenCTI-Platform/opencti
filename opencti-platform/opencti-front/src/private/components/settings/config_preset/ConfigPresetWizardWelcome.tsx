import React, { FunctionComponent } from 'react';
import { FileUploadOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import { Chip, Text } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

// The pre-built templates: their content is built by the domain experts, so they are disabled until it exists.
// Placeholders, so their texts are not translated: they are replaced when the templates exist.
const TEMPLATES = [
  { id: 'classic-cti', label: 'Classic CTI', description: 'Standard threat intelligence workspace: actors, malware, indicators and campaigns with ready made dashboards and trusted feeds.' },
  { id: 'fimi', label: 'FIMI/Disinformation', description: 'Foreign Information Manipulation & Interference: narratives, channels, and events tuned for tracking influence operations.' },
  { id: 'fraud', label: 'Fraud Prevention', description: 'Fraud-centric model: cases, accounts and transactions with detection dashboards and scoring workflows.' },
  { id: 'incident', label: 'Incident Management', description: 'Incident response oriented: incidents, cases and tasks with triage workflows and SLA dashboards.' },
];

interface ConfigPresetWizardWelcomeProps {
  // Starts the import of a zip; the button is disabled without it
  onImport?: () => void;
}

// First step: choose a template (coming later) or import a configuration bundle. There is no "start from scratch" choice: it is Close.
const ConfigPresetWizardWelcome: FunctionComponent<ConfigPresetWizardWelcomeProps> = ({ onImport }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }}>
      <Text variant="title-sm">{t_i18n('Choose one template')}</Text>
      <Text variant="content-base">
        {t_i18n('Select one of the options below, then click Next. A pre-built template is the fastest way to a working platform, you can fine tune everything afterwards.')}
      </Text>
      <div data-testid="config-preset-wizard-template" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: theme.spacing(2) }}>
        {TEMPLATES.map((template) => (
          <Card key={template.id} disabled onClick={() => undefined} aria-label={template.label}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1) }}>
              <Text variant="title-sm">{template.label}</Text>
              <Text variant="content-base">{template.description}</Text>
              <div><Chip label="Coming later" severity="neutral" /></div>
            </div>
          </Card>
        ))}
      </div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: theme.spacing(1) }}>
        <span data-testid="config-preset-wizard-import">
          <Button variant="secondary" startIcon={<FileUploadOutlined />} disabled={!onImport} onClick={onImport}>
            {t_i18n('Import config')}
          </Button>
        </span>
        <Button disabled>{t_i18n('Next')}</Button>
      </div>
    </div>
  );
};

export default ConfigPresetWizardWelcome;
