import React, { BaseSyntheticEvent, FunctionComponent, useRef } from 'react';
import VisuallyHiddenInput from '@components/common/VisuallyHiddenInput';
import { graphql } from 'react-relay';
import { FileUploadOutlined } from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton/ToggleButton';
import { FormImportMutation } from '@components/data/forms/__generated__/FormImportMutation.graphql';
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

interface FormImportProps {
  // Hide the upload toggle when the import is driven externally.
  hideTrigger?: boolean;
  // Called when the import completes (creation or error).
  onClose?: () => void;
}

const FormImport: FunctionComponent<FormImportProps> = ({ hideTrigger, onClose }) => {
  const inputFileRef = useRef<HTMLInputElement>(null);
  const { t_i18n } = useFormatter();
  const [commitImportMutation] = useApiMutation<FormImportMutation>(formImportMutation);

  const fileImport = (event: BaseSyntheticEvent) => {
    const file = event.target.files[0];
    if (!file) return;
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

  return (
    <>
      {!hideTrigger && (
        <ToggleButton
          value="import"
          size="small"
          sx={{ marginLeft: 1 }}
          title={t_i18n('Import form intake')}
          onClick={() => inputFileRef?.current?.click()}
        >
          <FileUploadOutlined fontSize="small" color="primary" />
        </ToggleButton>
      )}
      <VisuallyHiddenInput
        ref={inputFileRef}
        type="file"
        accept="application/json"
        onChange={fileImport}
      />
    </>
  );
};

export default FormImport;
