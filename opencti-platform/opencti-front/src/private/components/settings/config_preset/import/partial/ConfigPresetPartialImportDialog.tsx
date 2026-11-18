import React, { FunctionComponent, useState } from 'react';
import { useTheme } from '@mui/material/styles';
import Dialog from '@common/dialog/Dialog';
import type { Theme } from '../../../../../../components/Theme';
import ConfigPresetWizardStepper from '../../ConfigPresetWizardStepper';
import ConfigPresetPartialImportSourceChoice, { type ConfigPresetPartialImportSource } from './ConfigPresetPartialImportSourceChoice';
import ConfigPresetPartialImport from './ConfigPresetPartialImport';

const STEPS = ['Method', 'Select file', 'Done'];

type Step = 'method' | 'import' | 'done';
const STEP_INDEXES: Record<Step, number> = { method: 0, import: 1, done: 2 };

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
  // The file card is clicked: the screen opens the file picker of the import it already had, in the same click, and closes the dialog
  // once a file is picked. Its import stays as it was: no step, no result, the screen tells the outcome as before
  onChooseFile: () => void;
}

// The import dialog of a screen that offers the partial import. A click on a card is the choice: the import the screen already had opens
// its file picker at once; the bundle goes on in steps like the configuration preset wizard (the method, the file, the result).
// Generic: a screen gives its type, its texts and how to open its own file picker.
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
  onChooseFile,
}) => {
  const theme = useTheme<Theme>();
  const [step, setStep] = useState<Step>('method');
  const [source, setSource] = useState<ConfigPresetPartialImportSource | null>(null);
  // An import runs: the dialog is not dismissed, so that its result is not lost
  const [busy, setBusy] = useState(false);

  // Dismissal by the user (close button, escape, backdrop): refused while an import runs
  const handleClose = () => {
    if (!busy) {
      onClose();
      setStep('method');
      setSource(null);
    }
  };

  const handleSource = (chosen: ConfigPresetPartialImportSource) => {
    setSource(chosen);
    if (chosen === 'file') {
      onChooseFile();
    } else {
      setStep('import');
    }
  };

  return (
    <Dialog open={open} onClose={handleClose} title={title} showCloseButton={!busy}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(3) }}>
        <ConfigPresetWizardStepper activeStep={STEP_INDEXES[step]} steps={STEPS} />
        {step === 'method' ? (
          <ConfigPresetPartialImportSourceChoice
            value={source}
            onChange={handleSource}
            fileLabel={fileLabel}
            fileDescription={fileDescription}
            bundleDescription={bundleDescription}
          />
        ) : (
          // The bundle import shows its own result: it stays mounted for the last step
          <ConfigPresetPartialImport
            type={type}
            itemsLabel={itemsLabel}
            onImported={() => {
              onBundleImported();
              setStep('done');
            }}
            onBusyChange={setBusy}
            onBack={() => setStep('method')}
            onClose={handleClose}
          />
        )}
      </div>
    </Dialog>
  );
};

export default ConfigPresetPartialImportDialog;
