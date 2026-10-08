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
import { notifyPayloadErrors } from './hunt-mutation-utils';
import { UserContext } from '../../../utils/hooks/useAuth';
import { isNotEmptyField } from '../../../utils/utils';
import { useDataTableContext } from '../../../components/dataGrid/components/DataTableContext';
import { HuntPackExportQuery$data } from './__generated__/HuntPackExportQuery.graphql';
import { HuntPackImportMutation, HuntPackImportMutation$data } from './__generated__/HuntPackImportMutation.graphql';
import { HuntPackSelectionQuery$data, HuntPackSelectionQuery$variables } from './__generated__/HuntPackSelectionQuery.graphql';

export const huntPackExportQuery = graphql`
  query HuntPackExportQuery($ids: [ID!]!) {
    huntPackExport(ids: $ids)
  }
`;

export const huntPackSelectionQuery = graphql`
  query HuntPackSelectionQuery(
    $first: Int!
    $search: String
    $orderBy: HuntsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    hunts(first: $first, search: $search, orderBy: $orderBy, orderMode: $orderMode, filters: $filters) {
      edges {
        node {
          id
        }
      }
      pageInfo {
        globalCount
      }
    }
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
      created_count
      updated_count
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
  // A hunt the pack updated may already be listed: it is refreshed in place, never listed twice
  const listed = new Set((connection.getLinkedRecords('edges') ?? []).map((edge) => edge?.getLinkedRecord('node')?.getDataID()));
  hunts.forEach((hunt) => {
    if (hunt && !listed.has(hunt.getDataID())) {
      const edge = ConnectionHandler.createEdge(store, connection, hunt, 'HuntEdge');
      ConnectionHandler.insertEdgeBefore(connection, edge);
      listed.add(hunt.getDataID());
    }
  });
};

/** Success and warning messages of a hunt pack import, shared by the list and the XTM Hub deploy route. */
export const notifyHuntPackImport = (
  t_i18n: (message: string, options?: { values?: Record<string, string | number> }) => string,
  result: HuntPackImportMutation$data['huntPackImport'],
) => {
  const created = result?.created_count ?? 0;
  const updated = result?.updated_count ?? 0;
  const unresolvedCount = (result?.unresolved_refs ?? []).length;
  if (created > 0) {
    MESSAGING$.notifySuccess(t_i18n('{count} hunts imported as drafts', { values: { count: created } }));
  } else if (updated === 0) {
    // Nothing imported: why, and what to do next
    MESSAGING$.notifyError(unresolvedCount > 0
      ? t_i18n('No hunt of the hunt pack was imported: its hunts reference markings or objects unknown on this platform. Create them here, or import a pack whose references exist on this platform.')
      : t_i18n('No hunt of the hunt pack was imported: the file holds no hunt definition. Check that it is a hunt pack exported from OpenCTI or the XTM Hub (Hunt packs in the documentation).'));
  }
  if (updated > 0) {
    // Existing hunts keep how they run here (status, origin, schedule): only their definition changed
    MESSAGING$.notifySuccess(t_i18n('{count} existing hunts updated from the hunt pack', { values: { count: updated } }));
  }
  const unresolved = result?.unresolved_refs ?? [];
  if (unresolved.length > 0) {
    MESSAGING$.notifyError(t_i18n('{count} references of the hunt pack are unknown on this platform and were skipped', { values: { count: unresolved.length } }));
  }
};

/** Same limit as the hunt pack export of the platform */
export const HUNT_PACK_MAX_HUNTS = 200;

export type HuntPackSelectionOptions = Omit<HuntPackSelectionQuery$variables, 'first'>;

/**
 * Ids of every hunt matching the list options except the deselected ones, or null when they exceed the pack limit.
 * A select-all covers the hunts not loaded in the table yet, so the ids are resolved on the platform.
 */
export const resolveSelectAllHuntIds = async (
  options: HuntPackSelectionOptions,
  deSelectedElements: Record<string, unknown>,
): Promise<string[] | null> => {
  const deselected = Object.keys(deSelectedElements).length;
  const data = await fetchQuery(huntPackSelectionQuery, {
    search: options.search,
    orderBy: options.orderBy,
    orderMode: options.orderMode,
    filters: options.filters,
    first: HUNT_PACK_MAX_HUNTS + deselected,
  }).toPromise() as HuntPackSelectionQuery$data;
  const matching = data?.hunts?.pageInfo.globalCount ?? 0;
  const ids = (data?.hunts?.edges ?? [])
    .map((edge) => edge?.node?.id)
    .filter((id): id is string => !!id && !deSelectedElements[id]);
  if (matching - deselected > HUNT_PACK_MAX_HUNTS || ids.length > HUNT_PACK_MAX_HUNTS) {
    return null;
  }
  return ids;
};

interface HuntPackExportButtonProps {
  /** Exports these hunts; when absent, the hunts selected in the surrounding data table */
  ids?: string[];
  /** Query options of the surrounding data table, used to resolve a select-all */
  selectionOptions?: HuntPackSelectionOptions;
}

const SelectionExportButton = ({ selectionOptions }: { selectionOptions: HuntPackSelectionOptions }) => {
  const { t_i18n } = useFormatter();
  const {
    useDataTableToggle: { selectedElements, deSelectedElements, selectAll },
  } = useDataTableContext();
  const [exporting, setExporting] = useState(false);
  const selectedIds = Object.keys(selectedElements);
  const hasSelection = selectAll || selectedIds.length > 0;
  const label = hasSelection ? t_i18n('Export the selected hunts as a hunt pack') : t_i18n('Select the hunts to export as a hunt pack');
  const onExport = async () => {
    setExporting(true);
    try {
      const ids = selectAll ? await resolveSelectAllHuntIds(selectionOptions, deSelectedElements) : selectedIds;
      if (ids === null) {
        MESSAGING$.notifyError(t_i18n('A hunt pack holds at most {max} hunts, narrow the selection', { values: { max: HUNT_PACK_MAX_HUNTS } }));
      } else if (ids.length > 0) {
        await downloadHuntPack(ids);
      }
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
            disabled={!hasSelection || exporting}
            onClick={onExport}
            data-testid="hunt-pack-export"
          />
        </span>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
};

export const HuntPackExportButton = ({ ids, selectionOptions = {} }: HuntPackExportButtonProps) => {
  const { t_i18n } = useFormatter();
  const [exporting, setExporting] = useState(false);
  if (!ids) {
    return <SelectionExportButton selectionOptions={selectionOptions} />;
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

/** The hunt packs page of the XTM Hub for this platform, or null when the hub is not reachable. */
export const useHuntPackHubUrl = (): string | null => {
  const { settings, isXTMHubAccessible } = useContext(UserContext);
  if (!isXTMHubAccessible || !isNotEmptyField(settings?.platform_xtmhub_url)) {
    return null;
  }
  return `${settings?.platform_xtmhub_url}/redirect/opencti_hunt_packs?platform_id=${settings?.id}`;
};

interface HuntPackImportButtonProps {
  paginationOptions: Record<string, unknown>;
  /** The list of hunts offers the XTM Hub in its Quick start menu instead. */
  showHubLink?: boolean;
}

export const HuntPackImportButton = ({ paginationOptions, showHubLink = true }: HuntPackImportButtonProps) => {
  const { t_i18n } = useFormatter();
  const inputRef = useRef<HTMLInputElement>(null);
  const [commitImport, importing] = useApiMutation<HuntPackImportMutation>(huntPackImportMutation);
  const importFromHubUrl = useHuntPackHubUrl();

  const handleImport: InputHTMLAttributes<HTMLInputElement>['onChange'] = (event) => {
    const importedFile = event.target?.files?.[0];
    if (importedFile) {
      commitImport({
        variables: { file: importedFile },
        updater: (store) => insertImportedHunts(store, paginationOptions),
        onCompleted: (data, errors) => {
          if (!notifyPayloadErrors(errors)) {
            notifyHuntPackImport(t_i18n, data.huntPackImport);
          }
        },
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
      {showHubLink && importFromHubUrl && (
        <Button gradient href={importFromHubUrl} target="_blank" rel="noopener noreferrer" title={t_i18n('Import from XTM Hub')}>
          {t_i18n('Import from XTM Hub')}
        </Button>
      )}
    </>
  );
};
