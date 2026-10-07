import React, { useState } from 'react';
import { Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from '@filigran/design-system';
import { FileDownloadOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import { stixCoreObjectContentFilesUploadStixCoreObjectMutation } from '@components/common/stix_core_objects/StixCoreObjectContentFiles';
import {
  StixCoreObjectContentFilesUploadStixCoreObjectMutation,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectContentFilesUploadStixCoreObjectMutation.graphql';
import { useFormatter } from '../../../../components/i18n';
import { MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useGranted, { KNOWLEDGE_KNUPLOAD } from '../../../../utils/hooks/useGranted';
import { htmlToPdf } from '../../../../utils/htmlToPdf/htmlToPdf';
import { hasPayloadErrors } from './timeMachineMutations';

export type TimeMachineExportFormat = 'json' | 'csv' | 'pdf';

interface TimeMachineExportMenuProps {
  fileName: (extension: string) => string;
  buildJson: () => string;
  buildCsv: () => string;
  buildHtml: () => string;
  // When set, the export can also be stored in the files of this entity
  entityId?: string;
  disabled?: boolean;
}

const MIME_TYPES: Record<TimeMachineExportFormat, string> = {
  json: 'application/json',
  csv: 'text/csv',
  pdf: 'application/pdf',
};

const downloadBlob = (blob: Blob, name: string) => {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

/**
 * Export of a diff in JSON, CSV or PDF (built-in PDF generation), downloaded or stored
 * in the files of the entity through the standard file upload of the platform.
 */
const TimeMachineExportMenu = ({ fileName, buildJson, buildCsv, buildHtml, entityId, disabled = false }: TimeMachineExportMenuProps) => {
  const { t_i18n } = useFormatter();
  const [exporting, setExporting] = useState(false);
  const canUpload = useGranted([KNOWLEDGE_KNUPLOAD]);
  const [commitUpload, uploading] = useApiMutation<StixCoreObjectContentFilesUploadStixCoreObjectMutation>(
    stixCoreObjectContentFilesUploadStixCoreObjectMutation,
  );

  const buildBlob = async (format: TimeMachineExportFormat): Promise<Blob> => {
    if (format === 'json') return new Blob([buildJson()], { type: MIME_TYPES.json });
    if (format === 'csv') return new Blob([buildCsv()], { type: MIME_TYPES.csv });
    return htmlToPdf(fileName('html'), buildHtml()).getBlob();
  };

  const handleExport = async (format: TimeMachineExportFormat, store: boolean) => {
    setExporting(true);
    let blob: Blob;
    try {
      blob = await buildBlob(format);
    } catch {
      MESSAGING$.notifyError(t_i18n('Error trying to export the file'));
      setExporting(false);
      return;
    }
    const name = fileName(format);
    if (store && entityId) {
      commitUpload({
        variables: { id: entityId, file: new File([blob], name, { type: MIME_TYPES[format] }), noTriggerImport: true },
        onCompleted: (_, errors) => {
          setExporting(false);
          if (!hasPayloadErrors(errors)) {
            MESSAGING$.notifySuccess(t_i18n('The export has been saved in the files of the entity'));
          }
        },
        onError: () => setExporting(false),
      });
      return;
    }
    downloadBlob(blob, name);
    setExporting(false);
  };

  const formats: Array<{ format: TimeMachineExportFormat; label: string }> = [
    { format: 'json', label: t_i18n('Download as JSON') },
    { format: 'csv', label: t_i18n('Download as CSV') },
    { format: 'pdf', label: t_i18n('Download as PDF') },
  ];

  return (
    <Menu>
      <MenuTrigger asChild>
        <Button
          variant="secondary"
          startIcon={<FileDownloadOutlined fontSize="small" />}
          disabled={disabled || exporting || uploading}
          aria-label={t_i18n('Export')}
        >
          {t_i18n('Export')}
        </Button>
      </MenuTrigger>
      <MenuContent align="end">
        {formats.map(({ format, label }) => (
          <MenuItem key={format} onSelect={() => handleExport(format, false)}>{label}</MenuItem>
        ))}
        {entityId && canUpload && (
          <>
            <MenuSeparator />
            {formats.map(({ format }) => (
              <MenuItem key={`store-${format}`} onSelect={() => handleExport(format, true)}>
                {t_i18n('Save in the entity files as {format}', { values: { format: format.toUpperCase() } })}
              </MenuItem>
            ))}
          </>
        )}
      </MenuContent>
    </Menu>
  );
};

export default TimeMachineExportMenu;
