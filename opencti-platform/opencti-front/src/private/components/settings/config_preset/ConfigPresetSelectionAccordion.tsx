import React, { FunctionComponent, ReactNode, useId, useState } from 'react';
import { Checkbox } from '@filigran/design-system';
import { ChevronRightOutlined, ExpandLessOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../components/i18n';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { onActivationKey } from '../../../../utils/domEvent';
import EEChip from '../../common/entreprise_edition/EEChip';
import EETooltip from '../../common/entreprise_edition/EETooltip';
import type { Theme } from '../../../../components/Theme';
import {
  ConfigPresetForcedItems,
  ConfigPresetSelection,
  countConfigPresetCheckedItems,
  getConfigPresetCheckboxState,
  groupConfigPresetTypes,
  isConfigPresetTypeLocked,
  isSingletonConfigPresetType,
  toggleConfigPresetTypes,
} from './configPresetSelection';
import { ConfigPresetItemRow } from './ConfigPresetItemRow';

const toggleKey = (keys: readonly string[], key: string) => (keys.includes(key) ? keys.filter((current) => current !== key) : [...keys, key]);

interface ConfigPresetExpandableRowProps {
  label: string;
  description?: string;
  checked: boolean | 'indeterminate';
  disabled?: boolean;
  // Next to the chevron: a choice that applies to the rows below
  actions?: ReactNode;
  onCheckedChange: (checked: boolean) => void;
  expanded: boolean;
  onToggleExpanded: () => void;
  children: ReactNode;
}

// A checkbox with a chevron that shows or hides the rows below it (a group, or a type with several items)
const ConfigPresetExpandableRow: FunctionComponent<ConfigPresetExpandableRowProps> = ({
  label,
  description,
  checked,
  disabled,
  actions,
  onCheckedChange,
  expanded,
  onToggleExpanded,
  children,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const contentId = useId();
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: theme.spacing(1, 0) }}>
        <Checkbox label={label} description={description} checked={checked} disabled={disabled} onCheckedChange={(value) => onCheckedChange(value === true)} />
        <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
          {actions}
          <IconButton
            aria-label={`${expanded ? t_i18n('Collapse') : t_i18n('Expand')} ${label}`}
            aria-expanded={expanded}
            aria-controls={contentId}
            onClick={onToggleExpanded}
          >
            {expanded ? <ExpandLessOutlined /> : <ExpandMoreOutlined />}
          </IconButton>
        </div>
      </div>
      {expanded && (
        <div id={contentId} style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5), padding: theme.spacing(0, 0, 2, 3.5) }}>
          {children}
        </div>
      )}
    </div>
  );
};

interface AccordionItem {
  readonly key: string;
  readonly label: string;
  readonly translatable: boolean;
  readonly isDefault: boolean;
  readonly dependsOn: ReadonlyArray<{ readonly type: string; readonly key: string }>;
}

export interface ConfigPresetAccordionType {
  readonly key: string;
  readonly label: string;
  readonly description: string;
  readonly group: { readonly key: string; readonly label: string };
  readonly items: ReadonlyArray<AccordionItem>;
  readonly itemsPageInfo: { readonly globalCount: number; readonly hasNextPage?: boolean };
  // The type is part of the Enterprise Edition: without it its row opens the license dialog
  readonly requiresEnterpriseEdition?: boolean;
  // The backend cannot use the type now: it has no item
  readonly locked?: boolean;
}

// A type the platform cannot use: one row that stays unchecked, with the chip, and opens the license dialog. When the front end knows the
// platform has the license, the backend has not taken it into account yet: the row says so, and reads the types again when it is clicked.
const ConfigPresetLockedTypeRow: FunctionComponent<{ type: ConfigPresetAccordionType; title?: string; onRetry?: () => void }> = ({ type, title, onRetry }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const isEnterpriseEdition = useEnterpriseEdition();
  const retryTitle = t_i18n('The Enterprise Edition license is not taken into account yet, click to try again');
  // The row is the one button: named after the type, and its checkbox is out of the way of assistive tech, as in the gate of the license
  const retryProps = isEnterpriseEdition && onRetry
    ? { role: 'button', tabIndex: 0, 'aria-label': `${t_i18n(type.label)}. ${retryTitle}`, onClick: onRetry, onKeyDown: onActivationKey(onRetry) }
    : {};
  // The whole row is the button (it opens the license dialog, or reads again): its disabled checkbox and chip let the row's pointer cursor through
  return (
    <EETooltip title={isEnterpriseEdition ? 'The Enterprise Edition license is not taken into account yet, click to try again' : title}>
      <div style={{ cursor: !isEnterpriseEdition || onRetry ? 'pointer' : undefined }} {...retryProps}>
        <div aria-hidden={retryProps.role ? true : undefined} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: theme.spacing(1), pointerEvents: 'none' }}>
          <Checkbox label={t_i18n(type.label)} description={t_i18n(type.description)} checked={false} disabled />
          <EEChip feature={t_i18n(type.label)} size="sm" clickable={false} />
        </div>
      </div>
    </EETooltip>
  );
};

interface ConfigPresetSelectionAccordionProps<T extends ConfigPresetAccordionType> {
  types: ReadonlyArray<T>;
  selection: ConfigPresetSelection;
  forced: ConfigPresetForcedItems;
  onSelectionChange: (selection: ConfigPresetSelection) => void;
  disabled?: boolean;
  // A type with more items than its first page is managed in a sub-view (the export)
  onManageType?: (typeKey: string) => void;
  // The row of an item, the checkbox row of the export by default; also the only row of a type with a single item that has the key of the type
  renderItem?: (type: T, item: T['items'][number]) => ReactNode;
  // What is shown on the row of a type, next to its chevron (the choice for all its items)
  renderTypeActions?: (type: T) => ReactNode;
  // Types with several items start expanded (default false)
  expandTypes?: boolean;
  // The tooltip of a type that needs the Enterprise Edition the platform does not have yet, which opens the license dialog
  lockedTitle?: string;
  // Reads the types again: what a locked row does when clicked on a platform that has the license, which the backend has not taken into account yet
  onLockedRetry?: () => void;
}

// The groups, types and items of a bundle with their checkboxes, counts and chevrons: shared by the export drawer and the import preview
const ConfigPresetSelectionAccordion = <T extends ConfigPresetAccordionType>({
  types,
  selection,
  forced,
  onSelectionChange,
  disabled = false,
  onManageType,
  renderItem,
  renderTypeActions,
  expandTypes = false,
  lockedTitle,
  onLockedRetry,
}: ConfigPresetSelectionAccordionProps<T>) => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const isLocked = (type: T) => isConfigPresetTypeLocked(type, isEnterpriseEdition);
  // Groups start expanded, types with several items collapsed
  const [collapsedGroupKeys, setCollapsedGroupKeys] = useState<readonly string[]>([]);
  const [toggledTypeKeys, setToggledTypeKeys] = useState<readonly string[]>([]);
  const isExpanded = (type: T) => toggledTypeKeys.includes(type.key) !== expandTypes;
  const typeLabel = (type: T) => `${t_i18n(type.label)} (${countConfigPresetCheckedItems([type], selection, forced)}/${type.itemsPageInfo.globalCount})`;
  const typeState = (type: T) => getConfigPresetCheckboxState([type], selection, forced);
  const isEmpty = (type: T) => type.itemsPageInfo.globalCount === 0;
  const toggleType = (type: T, checked: boolean) => onSelectionChange(toggleConfigPresetTypes(selection, [type], checked));
  const theme = useTheme<Theme>();
  return (
    <div>
      {groupConfigPresetTypes(types).map((group) => (
        <div key={group.key} style={{ borderBottom: `1px solid ${theme.palette.divider}` }}>
          <ConfigPresetExpandableRow
            label={`${t_i18n(group.label)} (${countConfigPresetCheckedItems(group.types, selection, forced)}/${group.types.reduce((count, type) => count + type.itemsPageInfo.globalCount, 0)})`}
            checked={getConfigPresetCheckboxState(group.types, selection, forced)}
            disabled={disabled || group.types.every(isLocked)}
            onCheckedChange={(checked) => onSelectionChange(toggleConfigPresetTypes(selection, group.types, checked))}
            expanded={!collapsedGroupKeys.includes(group.key)}
            onToggleExpanded={() => setCollapsedGroupKeys((current) => toggleKey(current, group.key))}
          >
            {group.types.map((type) => {
              // Nothing of the type is listed, checked or counted until the platform has the license
              if (isLocked(type)) {
                return <ConfigPresetLockedTypeRow key={type.key} type={type} title={lockedTitle} onRetry={onLockedRetry} />;
              }
              // A type whose only item has the key of the type is one row, not a type with an item of the same name below it
              if (isSingletonConfigPresetType(type)) {
                if (renderItem) {
                  return <React.Fragment key={type.key}>{renderItem(type, type.items[0])}</React.Fragment>;
                }
                return (
                  <Checkbox
                    key={type.key}
                    label={t_i18n(type.label)}
                    description={t_i18n(type.description)}
                    checked={typeState(type)}
                    disabled={disabled}
                    onCheckedChange={(checked) => toggleType(type, checked === true)}
                  />
                );
              }
              if (onManageType && type.itemsPageInfo.hasNextPage) {
                return (
                  <div key={type.key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <Checkbox
                      label={typeLabel(type)}
                      description={t_i18n(type.description)}
                      checked={typeState(type)}
                      onCheckedChange={(checked) => toggleType(type, checked === true)}
                    />
                    <Button variant="tertiary" endIcon={<ChevronRightOutlined />} onClick={() => onManageType(type.key)}>
                      {t_i18n('Manage')}
                    </Button>
                  </div>
                );
              }
              return (
                <ConfigPresetExpandableRow
                  key={type.key}
                  label={typeLabel(type)}
                  description={t_i18n(type.description)}
                  checked={typeState(type)}
                  disabled={disabled || isEmpty(type)}
                  actions={renderTypeActions?.(type)}
                  onCheckedChange={(checked) => toggleType(type, checked)}
                  expanded={isExpanded(type)}
                  onToggleExpanded={() => setToggledTypeKeys((current) => toggleKey(current, type.key))}
                >
                  {type.items.map((item) => (renderItem
                    ? <React.Fragment key={item.key}>{renderItem(type, item)}</React.Fragment>
                    : <ConfigPresetItemRow key={item.key} typeKey={type.key} item={item} selection={selection} forced={forced} onSelectionChange={onSelectionChange} />))}
                </ConfigPresetExpandableRow>
              );
            })}
          </ConfigPresetExpandableRow>
        </div>
      ))}
    </div>
  );
};

export default ConfigPresetSelectionAccordion;
