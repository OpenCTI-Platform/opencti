import React, { FunctionComponent, ReactNode, useState } from 'react';
import { DialogActions } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../../../components/i18n';
import type { Theme } from '../../../../../../components/Theme';
import ConfigPresetWizardStepper from '../../ConfigPresetWizardStepper';
import ConfigPresetResultLine from '../ConfigPresetResultLine';
import ConfigPresetPartialImportSourceChoice, { type ConfigPresetPartialImportSource } from './ConfigPresetPartialImportSourceChoice';
import ConfigPresetPartialImport from './ConfigPresetPartialImport';

const STEPS = ['Method', 'Select file', 'Done'];

type Step = 'method' | 'import' | 'done';
const STEP_INDEXES: Record<Step, number> = { method: 0, import: 1, done: 2 };

// What the import of the screen hands to its step: it tells the dialog when it is done (the name of the item written) and while it runs
export interface ConfigPresetFileImportStepProps {
  onBack: () => void;
  onImported: (label: string) => void;
  onBusyChange: (busy: boolean) => void;
}

interface ConfigPresetPartialImportDialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  // The configuration preset type of the screen, and what the dialog calls its items (already translated)
  type: string;
  itemsLabel: string;
  // The cards of the first step, already translated
  fileLabel: string;
  fileDescription: string;
  bundleDescription: string;
  // After the import of items from the bundle, so that the screen reads its items again
  onBundleImported: () => void;
  // The second step of the file source: the import the screen already had (its own field, Back and Import)
  renderFileImport: (props: ConfigPresetFileImportStepProps) => ReactNode;
}

// The import dialog of a screen that offers the partial import, in three steps like the configuration preset wizard:
// 1. the method (the import of the screen, or the items of its type from a configuration bundle), 2. the file, 3. the result.
// Generic: a screen gives its type, its texts and its own file import.
const ConfigPresetPartialImportDialog: FunctionComponent<ConfigPresetPartialImportDialogProps> = ({
  open,
  onClose,
  title,
  type,
  itemsLabel,
  fileLabel,
  fileDescription,
  bundleDescription,
  onBundleImported,
  renderFileImport,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [step, setStep] = useState<Step>('method');
  const [source, setSource] = useState<ConfigPresetPartialImportSource | null>(null);
  // An import runs: the dialog is not dismissed, so that its result is not lost
  const [busy, setBusy] = useState(false);
  const [fileResult, setFileResult] = useState<string | null>(null);

  const closeDialog = () => {
    onClose();
    setStep('method');
    setSource(null);
    setFileResult(null);
  };
  // Dismissal by the user (close button, escape, backdrop, cancel): refused while an import runs
  const handleClose = () => {
    if (!busy) {
      closeDialog();
    }
  };
  const backToMethod = () => setStep('method');

  const renderStep = () => {
    if (step === 'method') {
      return (
        <>
          <ConfigPresetPartialImportSourceChoice
            value={source}
            onChange={setSource}
            fileLabel={fileLabel}
            fileDescription={fileDescription}
            bundleDescription={bundleDescription}
          />
          <DialogActions>
            <Button variant="secondary" onClick={handleClose}>{t_i18n('Cancel')}</Button>
            <Button onClick={() => setStep('import')} disabled={!source} data-testid="config-preset-partial-import-next">
              {t_i18n('Next')}
            </Button>
          </DialogActions>
        </>
      );
    }
    // The bundle import shows its own result: it stays mounted for the last step
    if (source === 'bundle') {
      return (
        <ConfigPresetPartialImport
          type={type}
          itemsLabel={itemsLabel}
          onImported={() => {
            onBundleImported();
            setStep('done');
          }}
          onBusyChange={setBusy}
          onBack={backToMethod}
          onClose={handleClose}
        />
      );
    }
    if (step === 'import') {
      return renderFileImport({
        onBack: backToMethod,
        onImported: (label) => {
          setFileResult(label);
          setStep('done');
        },
        onBusyChange: setBusy,
      });
    }
    return (
      <>
        <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5) }} data-testid="config-preset-partial-import-file-result">
          <Text variant="title-sm">{t_i18n('Import finished')}</Text>
          {fileResult && <ConfigPresetResultLine label={fileResult} status="CREATED" />}
        </div>
        <DialogActions>
          <Button onClick={handleClose}>{t_i18n('Close')}</Button>
        </DialogActions>
      </>
    );
  };

  return (
    <Dialog open={open} onClose={handleClose} title={title} showCloseButton={!busy}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(3) }}>
        <ConfigPresetWizardStepper activeStep={STEP_INDEXES[step]} steps={STEPS} />
        <div>{renderStep()}</div>
      </div>
    </Dialog>
  );
};

export default ConfigPresetPartialImportDialog;
