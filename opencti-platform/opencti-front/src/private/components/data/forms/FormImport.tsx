import React, { BaseSyntheticEvent, FunctionComponent, useRef, useState } from 'react';
import VisuallyHiddenInput from '@components/common/VisuallyHiddenInput';
import { graphql } from 'react-relay';
import { FileUploadOutlined } from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton';
import { FormImportMutation } from '@components/data/forms/__generated__/FormImportMutation.graphql';
import ConfigPresetPartialImportDialog from '@components/settings/config_preset/import/partial/ConfigPresetPartialImportDialog';
import useConfigPresetPartialImportAccess from '@components/settings/config_preset/import/partial/useConfigPresetPartialImportAccess';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleError, MESSAGING$ } from '../../../../relay/environment';

// Unlike the feed imports, a form intake import creates the form directly
// (there is no platform-specific field to choose before creation).
export const formImportMutation = graphql`
  mutation FormImportMutation($file: Upload!) {
    formImport(file: $file) {
      id
      name
    }
  }
`;

// The configuration preset type of the form intakes
const FORM_INTAKES_CONFIG_PRESET_TYPE = 'formIntakes';

interface FormImportProps {
  // Hide the upload toggle when the import is driven externally.
  hideTrigger?: boolean;
  // Called when the import completes (creation or error).
  onClose?: () => void;
}

const FormImport: FunctionComponent<FormImportProps> = ({ hideTrigger, onClose }) => {
  const inputFileRef = useRef<HTMLInputElement>(null);
  const { t_i18n } = useFormatter();
  const canImportFromBundle = useConfigPresetPartialImportAccess();
  const [open, setOpen] = useState(false);
  const [commitImportMutation] = useApiMutation<FormImportMutation>(formImportMutation);

  const fileImport = (event: BaseSyntheticEvent) => {
    const file = event.target.files[0];
    if (!file) return;
    // The file card of the dialog waits for a file: it closes once one is picked
    setOpen(false);
    commitImportMutation({
      variables: { file },
      onCompleted: () => {
        if (inputFileRef.current) {
          inputFileRef.current.value = '';
        }
        MESSAGING$.notifySuccess(t_i18n('Form intake successfully imported'));
        onClose?.();
      },
      onError: (error) => {
        if (inputFileRef.current) {
          inputFileRef.current.value = '';
        }
        handleError(error);
        onClose?.();
      },
    });
  };

  // A BYPASS user (flag on) chooses between the form intake file and a configuration bundle; the others pick a file at once, as before
  const handleTriggerClick = () => {
    if (canImportFromBundle) {
      setOpen(true);
    } else {
      inputFileRef.current?.click();
    }
  };

  return (
    <>
      {!hideTrigger && (
        <ToggleButton
          value="import"
          size="small"
          sx={{ marginLeft: 1 }}
          title={t_i18n('Import form intake')}
          onClick={handleTriggerClick}
        >
          <FileUploadOutlined fontSize="small" color="primary" />
        </ToggleButton>
      )}
      <VisuallyHiddenInput
        ref={inputFileRef}
        type="file"
        accept="application/json"
        onChange={fileImport}
        data-testid="import-form-intake-file"
      />
      {!hideTrigger && canImportFromBundle && (
        <ConfigPresetPartialImportDialog
          open={open}
          onClose={() => setOpen(false)}
          title={t_i18n('Import form intake')}
          type={FORM_INTAKES_CONFIG_PRESET_TYPE}
          itemsLabel={t_i18n('form intakes')}
          fileLabel={t_i18n('Import a form intake file')}
          fileDescription={t_i18n('A form intake exported as a JSON file')}
          bundleDescription={t_i18n('Select the form intakes to import from a full configuration bundle (zip)')}
          // The imported forms are read from the server by the screens that list them: nothing to refresh here
          onBundleImported={() => {}}
          onChooseFile={() => inputFileRef.current?.click()}
        />
      )}
    </>
  );
};

export default FormImport;
