import React, { FunctionComponent, ReactNode, Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Checkbox, Input, Text } from '@filigran/design-system';
import { ChevronRightOutlined, DownloadOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import Divider from '@mui/material/Divider';
import { useTheme } from '@mui/styles';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { Theme } from '../../../../components/Theme';
import { APP_BASE_PATH } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { ConfigPresetExportDrawerQuery } from './__generated__/ConfigPresetExportDrawerQuery.graphql';
import { ConfigPresetExportDrawerMutation } from './__generated__/ConfigPresetExportDrawerMutation.graphql';
import {
  buildConfigPresetSelections,
  ConfigPresetSelection,
  countConfigPresetCheckedItems,
  countConfigPresetItems,
  getConfigPresetCheckboxState,
  groupConfigPresetTypes,
  isSingletonConfigPresetType,
  selectAllConfigPresetItems,
  toggleConfigPresetItem,
  toggleConfigPresetTypes,
} from './configPresetSelection';

const BUNDLE_NAME_MAX_LENGTH = 80;

export const configPresetExportDrawerQuery = graphql`
  query ConfigPresetExportDrawerQuery {
    configPresetExportableTypes {
      key
      label
      group {
        key
        label
      }
      items {
        key
        label
        translatable
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

const toggleKey = (keys: readonly string[], key: string) => (keys.includes(key) ? keys.filter((current) => current !== key) : [...keys, key]);

interface ConfigPresetExpandableRowProps {
  label: string;
  checked: boolean | 'indeterminate';
  onCheckedChange: (checked: boolean) => void;
  expanded: boolean;
  onToggleExpanded: () => void;
  children: ReactNode;
}

// A checkbox with a chevron that shows or hides the rows below it (a group, or a type with several items)
const ConfigPresetExpandableRow: FunctionComponent<ConfigPresetExpandableRowProps> = ({ label, checked, onCheckedChange, expanded, onToggleExpanded, children }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: theme.spacing(1, 0) }}>
        <Checkbox label={label} checked={checked} onCheckedChange={(value) => onCheckedChange(value === true)} />
        <IconButton
          aria-label={expanded ? t_i18n('Collapse') : t_i18n('Expand')}
          aria-expanded={expanded}
          onClick={onToggleExpanded}
        >
          {expanded ? <ExpandMoreOutlined /> : <ChevronRightOutlined />}
        </IconButton>
      </div>
      {expanded && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5), padding: theme.spacing(0, 0, 2, 3.5) }}>
          {children}
        </div>
      )}
    </div>
  );
};

type ExportableTypes = ConfigPresetExportDrawerQuery['response']['configPresetExportableTypes'];

interface ConfigPresetExportContentProps {
  types: ExportableTypes;
  onClose: () => void;
}

const ConfigPresetExportContent: FunctionComponent<ConfigPresetExportContentProps> = ({ types, onClose }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [selection, setSelection] = useState<ConfigPresetSelection>(() => selectAllConfigPresetItems(types));
  // Groups start expanded, types with several items collapsed
  const [collapsedGroupKeys, setCollapsedGroupKeys] = useState<readonly string[]>([]);
  const [expandedTypeKeys, setExpandedTypeKeys] = useState<readonly string[]>([]);
  const [bundleName, setBundleName] = useState('');
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

  return (
    <>
      <div style={{ flexGrow: 1, overflowY: 'auto', padding: theme.spacing(3), display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }}>
        <Text variant="content-base">
          {t_i18n('Select all the elements to include in your configuration bundle')}
        </Text>
        <div>
          {groupConfigPresetTypes(types).map((group) => (
            <div key={group.key} style={{ borderBottom: `1px solid ${theme.palette.divider}` }}>
              <ConfigPresetExpandableRow
                label={`${t_i18n(group.label)} (${countConfigPresetCheckedItems(group.types, selection)}/${countConfigPresetItems(group.types)})`}
                checked={getConfigPresetCheckboxState(group.types, selection)}
                onCheckedChange={(checked) => setSelection(toggleConfigPresetTypes(selection, group.types, checked))}
                expanded={!collapsedGroupKeys.includes(group.key)}
                onToggleExpanded={() => setCollapsedGroupKeys((current) => toggleKey(current, group.key))}
              >
                {group.types.map((type) => (isSingletonConfigPresetType(type) ? (
                  <Checkbox
                    key={type.key}
                    label={t_i18n(type.label)}
                    checked={getConfigPresetCheckboxState([type], selection)}
                    onCheckedChange={(checked) => setSelection(toggleConfigPresetTypes(selection, [type], checked === true))}
                  />
                ) : (
                  <ConfigPresetExpandableRow
                    key={type.key}
                    label={`${t_i18n(type.label)} (${countConfigPresetCheckedItems([type], selection)}/${type.items.length})`}
                    checked={getConfigPresetCheckboxState([type], selection)}
                    onCheckedChange={(checked) => setSelection(toggleConfigPresetTypes(selection, [type], checked))}
                    expanded={expandedTypeKeys.includes(type.key)}
                    onToggleExpanded={() => setExpandedTypeKeys((current) => toggleKey(current, type.key))}
                  >
                    {type.items.map((item) => (
                      <Checkbox
                        key={item.key}
                        label={item.translatable ? t_i18n(item.label) : item.label}
                        checked={selection[type.key]?.includes(item.key) ?? false}
                        onCheckedChange={(checked) => setSelection(toggleConfigPresetItem(selection, type.key, item.key, checked === true))}
                      />
                    ))}
                  </ConfigPresetExpandableRow>
                )))}
              </ConfigPresetExpandableRow>
            </div>
          ))}
        </div>
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
}

const ConfigPresetExportForm: FunctionComponent<ConfigPresetExportFormProps> = ({ queryRef, onClose }) => {
  const { configPresetExportableTypes } = usePreloadedQuery(configPresetExportDrawerQuery, queryRef);
  // A type without item has nothing to check: it is not shown, and neither is a group left without type
  const types = configPresetExportableTypes.filter((type) => type.items.length > 0);
  // The selection starts with every item checked: the content is remounted when the catalog changes,
  // as the cached catalog is first rendered and then replaced by the network one
  const catalogKey = types.flatMap((type) => type.items.map((item) => `${type.key}/${item.key}`)).join(',');
  return <ConfigPresetExportContent key={catalogKey} types={types} onClose={onClose} />;
};

// The drawer content is only mounted while it is open, so the catalog is loaded on demand
const ConfigPresetExportLoader: FunctionComponent<{ onClose: () => void }> = ({ onClose }) => {
  const queryRef = useQueryLoading<ConfigPresetExportDrawerQuery>(configPresetExportDrawerQuery, {});
  if (!queryRef) {
    return <Loader variant={LoaderVariant.inElement} />;
  }
  return (
    <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <ConfigPresetExportForm queryRef={queryRef} onClose={onClose} />
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
