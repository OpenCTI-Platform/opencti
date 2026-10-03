import React, { InputHTMLAttributes, useContext, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import { ConnectionHandler, RecordSourceSelectorProxy } from 'relay-runtime';
import { FileDownloadOutlined, FileUploadOutlined } from '@mui/icons-material';
import { IconButton, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import fileDownload from 'js-file-download';
import Button from '@common/button/Button';
import VisuallyHiddenInput from '../common/VisuallyHiddenInput';
import { useFormatter } from '../../../components/i18n';
import { fetchQuery, MESSAGING$ } from '../../../relay/environment';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { UserContext } from '../../../utils/hooks/useAuth';
import { isNotEmptyField } from '../../../utils/utils';
import { useDataTableContext } from '../../../components/dataGrid/components/DataTableContext';
import { HuntPackExportQuery$data } from './__generated__/HuntPackExportQuery.graphql';
import { HuntPackImportMutation, HuntPackImportMutation$data } from './__generated__/HuntPackImportMutation.graphql';

export const huntPackExportQuery = graphql`
  query HuntPackExportQuery($ids: [ID!]!) {
    huntPackExport(ids: $ids)
  }
`;

export const huntPackImportMutation = graphql`
  mutation HuntPackImportMutation($file: Upload!) {
    huntPackImport(file: $file) {
      hunts {
        id
        name
        ...Hunts_HuntFragment
      }
      unresolved_refs
    }
  }
`;

const packFileName = (count: number) => {
  const [day, month, year] = new Date().toLocaleDateString('fr-FR').split('/');
  return `${year}${month}${day}_opencti_hunt_pack_${count}.json`;
};

/** Downloads the STIX 2.1 bundle (hunt pack) of the given hunts. */
export const downloadHuntPack = async (ids: string[]) => {
  const data = await fetchQuery(huntPackExportQuery, { ids }).toPromise() as HuntPackExportQuery$data;
  if (data?.huntPackExport) {
    fileDownload(new Blob([data.huntPackExport], { type: 'application/json' }), packFileName(ids.length));
  }
};

/** Inserts the imported hunts at the top of the hunts list. */
export const insertImportedHunts = (
  store: RecordSourceSelectorProxy,
  paginationOptions: Record<string, unknown>,
) => {
  const payload = store.getRootField('huntPackImport');
  const hunts = payload?.getLinkedRecords('hunts') ?? [];
  const { count: _count, ...params } = paginationOptions;
  const connection = ConnectionHandler.getConnection(store.getRoot(), 'Pagination_hunts', params);
  if (!connection) {
    return;
  }
  hunts.forEach((hunt) => {
    if (hunt) {
      const edge = ConnectionHandler.createEdge(store, connection, hunt, 'HuntEdge');
      ConnectionHandler.insertEdgeBefore(connection, edge);
    }
  });
};

/** Success and warning messages of a hunt pack import, shared by the list and the XTM Hub deploy route. */
export const notifyHuntPackImport = (
  t_i18n: (message: string, options?: { values?: Record<string, string | number> }) => string,
  result: HuntPackImportMutation$data['huntPackImport'],
) => {
  const count = result?.hunts.length ?? 0;
  MESSAGING$.notifySuccess(t_i18n('{count} hunts imported as drafts', { values: { count } }));
  const unresolved = result?.unresolved_refs ?? [];
  if (unresolved.length > 0) {
    MESSAGING$.notifyError(t_i18n('{count} references of the hunt pack are unknown on this platform and were skipped', { values: { count: unresolved.length } }));
  }
};

interface HuntPackExportButtonProps {
  /** Exports these hunts; when absent, the hunts selected in the surrounding data table */
  ids?: string[];
}

const SelectionExportButton = () => {
  const { t_i18n } = useFormatter();
  const {
    useDataTableToggle: { selectedElements, deSelectedElements, selectAll },
    data,
    resolvePath,
  } = useDataTableContext();
  const [exporting, setExporting] = useState(false);
  // The header buttons render before the first page of the table is loaded
  const loaded = (((data ? resolvePath(data) : null) ?? []) as ({ id: string } | null)[]).filter((node): node is { id: string } => !!node);
  const ids = selectAll
    ? loaded.map((node) => node.id).filter((id) => !deSelectedElements[id])
    : Object.keys(selectedElements);
  const label = ids.length > 0 ? t_i18n('Export the selected hunts as a hunt pack') : t_i18n('Select the hunts to export as a hunt pack');
  const onExport = async () => {
    setExporting(true);
    try {
      await downloadHuntPack(ids);
    } finally {
      setExporting(false);
    }
  };
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span>
          <IconButton
            priority="tertiary"
            aria-label={label}
            icon={<FileDownloadOutlined fontSize="small" aria-hidden />}
            disabled={ids.length === 0 || exporting}
            onClick={onExport}
            data-testid="hunt-pack-export"
          />
        </span>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
};

export const HuntPackExportButton = ({ ids }: HuntPackExportButtonProps) => {
  const { t_i18n } = useFormatter();
  const [exporting, setExporting] = useState(false);
  if (!ids) {
    return <SelectionExportButton />;
  }
  const onExport = async () => {
    setExporting(true);
    try {
      await downloadHuntPack(ids);
    } finally {
      setExporting(false);
    }
  };
  return (
    <Button variant="secondary" size="small" onClick={onExport} disabled={exporting} startIcon={<FileDownloadOutlined fontSize="small" />}>
      {t_i18n('Export as hunt pack')}
    </Button>
  );
};

interface HuntPackImportButtonProps {
  paginationOptions: Record<string, unknown>;
}

export const HuntPackImportButton = ({ paginationOptions }: HuntPackImportButtonProps) => {
  const { t_i18n } = useFormatter();
  const inputRef = useRef<HTMLInputElement>(null);
  const { settings, isXTMHubAccessible } = useContext(UserContext);
  const [commitImport, importing] = useApiMutation<HuntPackImportMutation>(huntPackImportMutation);
  const importFromHubUrl = isNotEmptyField(settings?.platform_xtmhub_url)
    ? `${settings?.platform_xtmhub_url}/redirect/opencti_hunt_packs?platform_id=${settings?.id}`
    : '';

  const handleImport: InputHTMLAttributes<HTMLInputElement>['onChange'] = (event) => {
    const importedFile = event.target?.files?.[0];
    if (importedFile) {
      commitImport({
        variables: { file: importedFile },
        updater: (store) => insertImportedHunts(store, paginationOptions),
        onCompleted: (data) => notifyHuntPackImport(t_i18n, data.huntPackImport),
      });
    }
    if (inputRef.current) {
      inputRef.current.value = '';
    }
  };

  const label = t_i18n('Import a hunt pack');
  return (
    <>
      <VisuallyHiddenInput
        ref={inputRef}
        type="file"
        accept="application/json,.json"
        onChange={handleImport}
        data-testid="hunt-pack-import-input"
      />
      <Tooltip>
        <TooltipTrigger asChild>
          <span>
            <IconButton
              priority="tertiary"
              aria-label={label}
              icon={<FileUploadOutlined fontSize="small" aria-hidden />}
              disabled={importing}
              onClick={() => inputRef.current?.click()}
              data-testid="hunt-pack-import"
            />
          </span>
        </TooltipTrigger>
        <TooltipContent>{label}</TooltipContent>
      </Tooltip>
      {isXTMHubAccessible && isNotEmptyField(importFromHubUrl) && (
        <Button gradient href={importFromHubUrl} target="_blank" rel="noopener noreferrer" title={t_i18n('Import from Hub')}>
          {t_i18n('Import from Hub')}
        </Button>
      )}
    </>
  );
};
