import React, { BaseSyntheticEvent, FunctionComponent, useRef, useState } from 'react';
import VisuallyHiddenInput from '@components/common/VisuallyHiddenInput';
import { graphql } from 'react-relay';
import { FileUploadOutlined } from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton/ToggleButton';
import { IngestionJsonCreationContainer, IngestionJsonImportedInput } from '@components/data/ingestionJson/IngestionJsonCreation';
import { IngestionJsonLinesPaginationQuery$variables } from '@components/data/ingestionJson/__generated__/IngestionJsonLinesPaginationQuery.graphql';
import { IngestionJsonImportMutation } from '@components/data/ingestionJson/__generated__/IngestionJsonImportMutation.graphql';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleError } from '../../../../relay/environment';

// A mutation (not a query) because the embedded JSON mapper is created when no
// existing mapper matches the imported one.
export const ingestionJsonImportMutation = graphql`
  mutation IngestionJsonImportMutation($file: Upload!) {
    ingestionJsonAddInputFromImport(file: $file) {
      name
      description
      scheduling_period
      uri
      verb
      body
      pagination_with_sub_page
      pagination_with_sub_page_attribute_path
      pagination_with_sub_page_query_verb
      headers {
        name
        value
      }
      query_attributes {
        type
        from
        to
        data_operation
        state_operation
        default
        exposed
      }
      authentication_type
      ssl_verify
      jsonMapper {
        id
        name
      }
    }
  }
`;

interface IngestionJsonImportProps {
  paginationOptions?: IngestionJsonLinesPaginationQuery$variables | null | undefined;
  // Hide the upload toggle when the import is driven externally.
  hideTrigger?: boolean;
  // Called when the prefilled creation drawer closes (creation or cancel).
  onClose?: () => void;
}

const IngestionJsonImport: FunctionComponent<IngestionJsonImportProps> = ({ paginationOptions, hideTrigger, onClose }) => {
  const inputFileRef = useRef<HTMLInputElement>(null);
  const [open, setOpen] = useState<boolean>(false);
  const [importedInput, setImportedInput] = useState<IngestionJsonImportedInput | null>(null);
  const { t_i18n } = useFormatter();
  const [commitImportMutation] = useApiMutation<IngestionJsonImportMutation>(ingestionJsonImportMutation);

  const fileImport = (event: BaseSyntheticEvent) => {
    const file = event.target.files[0];
    if (!file) return;
    commitImportMutation({
      variables: { file },
      onCompleted: (data) => {
        setImportedInput(data.ingestionJsonAddInputFromImport as IngestionJsonImportedInput);
        setOpen(true);
        if (inputFileRef.current) {
          inputFileRef.current.value = '';
        }
      },
      onError: (error) => {
        if (inputFileRef.current) {
          inputFileRef.current.value = '';
        }
        handleError(error);
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
          title={t_i18n('Import a JSON feed')}
          onClick={() => inputFileRef?.current?.click()}
        >
          <FileUploadOutlined fontSize="small" color="primary" />
        </ToggleButton>
      )}
      <VisuallyHiddenInput
        ref={inputFileRef}
        type="file"
        accept="application/JSON"
        onChange={fileImport}
      />
      <IngestionJsonCreationContainer
        open={open}
        handleClose={() => {
          setOpen(false);
          onClose?.();
        }}
        importedInput={importedInput}
        paginationOptions={paginationOptions}
        isDuplicated={false}
        triggerButton={false}
        drawerSettings={{
          title: t_i18n('Import a JSON feed'),
          button: t_i18n('Create'),
        }}
      />
    </>
  );
};

export default IngestionJsonImport;
