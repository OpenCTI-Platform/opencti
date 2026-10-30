import React, { FunctionComponent, Suspense, useCallback, useEffect, useRef, useState } from 'react';
import { graphql, PreloadedQuery, useQueryLoader, usePreloadedQuery } from 'react-relay';
import { Input, Text } from '@filigran/design-system';
import { DownloadOutlined } from '@mui/icons-material';
import Divider from '@mui/material/Divider';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import type { Theme } from '../../../../../components/Theme';
import { APP_BASE_PATH } from '../../../../../relay/environment';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';
import { ConfigPresetExportDrawerQuery } from './__generated__/ConfigPresetExportDrawerQuery.graphql';
import { ConfigPresetExportDrawerMutation } from './__generated__/ConfigPresetExportDrawerMutation.graphql';
import { buildConfigPresetSelections, ConfigPresetSelection, getConfigPresetForcedItems, selectAllConfigPresetItems } from '../configPresetSelection';
import ConfigPresetExportItems from './ConfigPresetExportItems';
import ConfigPresetSelectionAccordion from '../ConfigPresetSelectionAccordion';
import useConfigPresetLicenseRetry from '../useConfigPresetLicenseRetry';

const BUNDLE_NAME_MAX_LENGTH = 80;

export const configPresetExportDrawerQuery = graphql`
  query ConfigPresetExportDrawerQuery {
    configPresetExportableTypes {
      key
      label
      description
      lockedByEnterpriseEdition
      group {
        key
        label
      }
      items {
        key
        label
        translatable
        isDefault
        dependsOn {
          type
          key
        }
      }
      itemsPageInfo {
        hasNextPage
        globalCount
      }
    }
  }
`;

const configPresetExportDrawerMutation = graphql`
  mutation ConfigPresetExportDrawerMutation($selections: [ConfigPresetSelectionInput!]!, $bundle_name: String) {
    configPresetExport(selections: $selections, bundle_name: $bundle_name) {
      id
    }
  }
`;

type ExportableTypes = ConfigPresetExportDrawerQuery['response']['configPresetExportableTypes'];

interface ConfigPresetExportContentProps {
  types: ExportableTypes;
  onClose: () => void;
  onLockedRetry: () => void;
}

const ConfigPresetExportContent: FunctionComponent<ConfigPresetExportContentProps> = ({ types, onClose, onLockedRetry }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [selection, setSelection] = useState<ConfigPresetSelection>(() => selectAllConfigPresetItems(types));
  const [bundleName, setBundleName] = useState('');
  // The type whose items are managed in the sub-view, when it has more items than its first page
  const [managedTypeKey, setManagedTypeKey] = useState<string | null>(null);
  const forced = getConfigPresetForcedItems(types, selection);
  const managedType = types.find((type) => type.key === managedTypeKey);
  const [commitExport, exporting] = useApiMutation<ConfigPresetExportDrawerMutation>(configPresetExportDrawerMutation);
  const selections = buildConfigPresetSelections(types, selection);

  const handleExport = () => {
    commitExport({
      variables: { selections, bundle_name: bundleName.trim() || null },
      onCompleted: (response) => {
        window.location.href = `${APP_BASE_PATH}/storage/get/${encodeURIComponent(response.configPresetExport.id)}`;
        onClose();
      },
    });
  };

  if (managedType) {
    return (
      <ConfigPresetExportItems
        type={managedType}
        selection={selection}
        forced={forced}
        onSelectionChange={setSelection}
        onBack={() => setManagedTypeKey(null)}
      />
    );
  }

  return (
    <>
      <div style={{ flexGrow: 1, overflowY: 'auto', padding: theme.spacing(3), display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }}>
        <Text variant="content-base">
          {t_i18n('Select all the elements to include in your configuration bundle')}
        </Text>
        <ConfigPresetSelectionAccordion
          types={types}
          selection={selection}
          forced={forced}
          onSelectionChange={setSelection}
          onManageType={setManagedTypeKey}
          lockedTitle="Activate the Enterprise Edition to export this item"
          onLockedRetry={onLockedRetry}
        />
        <Input
          label={t_i18n('Bundle name')}
          value={bundleName}
          maxLength={BUNDLE_NAME_MAX_LENGTH}
          onChange={(event) => setBundleName(event.target.value)}
        />
      </div>
      <Divider />
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: theme.spacing(1.5), padding: theme.spacing(3) }}>
        <Button variant="secondary" onClick={onClose}>
          {t_i18n('Cancel')}
        </Button>
        <Button startIcon={<DownloadOutlined />} onClick={handleExport} loading={exporting} disabled={exporting || selections.length === 0}>
          {t_i18n('Export Platform Bundle')}
        </Button>
      </div>
    </>
  );
};

interface ConfigPresetExportFormProps {
  queryRef: PreloadedQuery<ConfigPresetExportDrawerQuery>;
  onClose: () => void;
  onReload: () => void;
}

const ConfigPresetExportForm: FunctionComponent<ConfigPresetExportFormProps> = ({ queryRef, onClose, onReload }) => {
  const { configPresetExportableTypes } = usePreloadedQuery(configPresetExportDrawerQuery, queryRef);
  const retryLocked = useConfigPresetLicenseRetry(configPresetExportableTypes, onReload);
  // A type without item has nothing to check: it is not shown, and neither is a group left without type. A type the platform cannot use
  // (it needs the Enterprise Edition the platform does not have) is shown, locked.
  const types = configPresetExportableTypes.filter((type) => type.items.length > 0 || type.lockedByEnterpriseEdition);
  // The selection starts with every item checked: the content is remounted when the catalog changes, as the cached catalog is first
  // rendered and then replaced by the network one. A type that was locked is not part of the key: a license activated while the drawer
  // is open adds its items to the catalog, and the selection made until then is kept (it comes checked, as the selection holds every type).
  const lockedKeysRef = useRef(new Set<string>());
  configPresetExportableTypes.forEach((type) => type.lockedByEnterpriseEdition && lockedKeysRef.current.add(type.key));
  const catalogKey = types.filter((type) => !lockedKeysRef.current.has(type.key)).flatMap((type) => type.items.map((item) => `${type.key}/${item.key}`)).join(',');
  return <ConfigPresetExportContent key={catalogKey} types={types} onClose={onClose} onLockedRetry={retryLocked} />;
};

// The drawer content is only mounted while it is open, so the catalog is loaded on demand
// and read again when a license is activated, which adds the types that need it
const ConfigPresetExportLoader: FunctionComponent<{ onClose: () => void }> = ({ onClose }) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const [queryRef, loadQuery] = useQueryLoader<ConfigPresetExportDrawerQuery>(configPresetExportDrawerQuery);
  const reload = useCallback(() => loadQuery({}, { fetchPolicy: 'store-and-network' }), [loadQuery]);
  useEffect(() => {
    reload();
  }, [reload, isEnterpriseEdition]);
  if (!queryRef) {
    return <Loader variant={LoaderVariant.inElement} />;
  }
  return (
    <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <ConfigPresetExportForm queryRef={queryRef} onClose={onClose} onReload={reload} />
    </Suspense>
  );
};

interface ConfigPresetExportDrawerProps {
  open: boolean;
  onClose: () => void;
}

const ConfigPresetExportDrawer: FunctionComponent<ConfigPresetExportDrawerProps> = ({ open, onClose }) => {
  const { t_i18n } = useFormatter();
  return (
    <Drawer
      title={t_i18n('Platform Bundle')}
      open={open}
      onClose={onClose}
      size="medium"
      containerStyle={{ padding: 0, gap: 0, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}
    >
      {({ onClose: handleClose }) => <ConfigPresetExportLoader onClose={handleClose} />}
    </Drawer>
  );
};

export default ConfigPresetExportDrawer;
