import React, { BaseSyntheticEvent, FunctionComponent, useRef, useState } from 'react';
import VisuallyHiddenInput from '@components/common/VisuallyHiddenInput';
import { graphql } from 'react-relay';
import { FileUploadOutlined } from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton/ToggleButton';
import IngestionTaxiiCollectionCreation from '@components/data/ingestionTaxiiCollection/IngestionTaxiiCollectionCreation';
import { IngestionTaxiiCollectionImportQuery$data } from '@components/data/ingestionTaxiiCollection/__generated__/IngestionTaxiiCollectionImportQuery.graphql';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { PaginationOptions } from '../../../../components/list_lines';

export const taxiiCollectionImportQuery = graphql`
  query IngestionTaxiiCollectionImportQuery($file: Upload!) {
    ingestionTaxiiCollectionAddInputFromImport(file: $file) {
      name
      description
      confidence_to_score
    }
  }
`;

interface IngestionTaxiiCollectionImportProps {
  paginationOptions?: PaginationOptions;
  // Hide the upload toggle when the import is driven externally.
  hideTrigger?: boolean;
  // Called when the prefilled creation drawer closes (creation or cancel).
  onClose?: () => void;
}

const IngestionTaxiiCollectionImport: FunctionComponent<IngestionTaxiiCollectionImportProps> = ({ paginationOptions, hideTrigger, onClose }) => {
  const inputFileRef = useRef<HTMLInputElement>(null);
  const [open, setOpen] = useState<boolean>(false);
  const [importedInput, setImportedInput] = useState<IngestionTaxiiCollectionImportQuery$data['ingestionTaxiiCollectionAddInputFromImport'] | undefined>(undefined);
  const { t_i18n } = useFormatter();

  const fileImport = async (event: BaseSyntheticEvent) => {
    const file = event.target.files[0];
    if (!file) return;
    try {
      const data = await fetchQuery(taxiiCollectionImportQuery, { file }).toPromise();
      const { ingestionTaxiiCollectionAddInputFromImport } = data as IngestionTaxiiCollectionImportQuery$data;
      setImportedInput(ingestionTaxiiCollectionAddInputFromImport);
      setOpen(true);
      if (inputFileRef.current) {
        inputFileRef.current.value = '';
      }
    } catch (e) {
      MESSAGING$.notifyRelayError(e);
    }
  };

  return (
    <>
      {!hideTrigger && (
        <ToggleButton
          value="import"
          size="small"
          sx={{ marginLeft: 1 }}
          title={t_i18n('Import a TAXII Push ingester')}
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
      <IngestionTaxiiCollectionCreation
        open={open}
        handleClose={() => {
          setOpen(false);
          onClose?.();
        }}
        importedInput={importedInput}
        paginationOptions={paginationOptions}
        drawerSettings={{
          title: t_i18n('Import a TAXII Push ingester'),
          button: t_i18n('Create'),
        }}
      />
    </>
  );
};

export default IngestionTaxiiCollectionImport;
