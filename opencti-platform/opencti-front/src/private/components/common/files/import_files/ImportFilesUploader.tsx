import React, { useState } from 'react';
import { Grid } from '@mui/material';
import ImportFilesDropzone from '@components/common/files/import_files/ImportFilesDropzone';
import ImportFilesFreeText from '@components/common/files/import_files/ImportFilesFreeText';
import ImportFilesList from '@components/common/files/import_files/ImportFilesList';
import { useImportFilesContext } from '@components/common/files/import_files/ImportFilesContext';
import { ImportFilesContextQuery$data } from '@components/common/files/import_files/__generated__/ImportFilesContextQuery.graphql';

export type FileWithConnectors = {
  file: File;
  connectors?: { id: string; name: string; }[];
  configuration?: string;
};

interface ImportFilesUploaderProps {
  connectorsForImport: ImportFilesContextQuery$data['connectorsForImport'];
}

const ImportFilesUploader = ({ connectorsForImport }: ImportFilesUploaderProps) => {
  const { files, setFiles } = useImportFilesContext();
  const [isTextView, setIsTextView] = useState(false);

  const updateFiles = (newFiles: File[]) => {
    const extendedFiles: FileWithConnectors[] = newFiles.map((file) => {
      const connectors = connectorsForImport?.reduce<FileWithConnectors['connectors']>((acc, connector) => {
        if (connector?.active && connector?.connector_scope?.includes(file.type)) {
          acc?.push({ id: connector.id, name: connector.name });
        }
        return acc;
      }, []);

      return connectors && connectors.length > 0 ? { file, connectors } : { file };
    });

    setFiles([...files, ...extendedFiles]);
  };

  return (
    <Grid container>
      <Grid item xs={12}>
        { !isTextView ? (
          <ImportFilesDropzone
            fullSize={files.length === 0}
            onChange={updateFiles}
            openFreeText={() => setIsTextView(true)}
          />
        ) : (
          <ImportFilesFreeText onSumbit={(file) => {
            updateFiles([file]);
            setIsTextView(false);
          }}
            onClose={ () => setIsTextView(false) }
          />
        )}
      </Grid>

      <Grid item xs={12}>
        <ImportFilesList connectorsForImport={connectorsForImport}/>
      </Grid>
    </Grid>
  );
};

export default ImportFilesUploader;
