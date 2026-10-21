import React, { ReactNode } from 'react';
import { Box } from '@mui/material';
import { alpha, useTheme } from '@mui/material/styles';
import { Checkbox, IconButton, Menu, MenuContent, MenuItem, MenuTrigger, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { CheckOutlined, CloseOutlined, RestoreOutlined, SwapHorizOutlined, WarningAmberOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import ItemEntityType from '../../../../components/ItemEntityType';
import { itemColor } from '../../../../utils/Colors';
import { MAIN_CONTENT_SOURCE, ReviewItem } from './contentMappingModel';
import { hashAlgorithmOf, isDefanged, refangValue, typeCandidates } from './mappingValue';
import { canCreateType } from './useContentMappingActions';

interface MappingRowProps {
  item: ReviewItem;
  occurrences: number;
  selected: boolean;
  active: boolean;
  sourceLabel: (source: string) => string;
  onToggle: () => void;
  onHover: (hovered: boolean) => void;
  onAccept?: () => void;
  onReject?: () => void;
  onRestore?: () => void;
  onUnmap?: () => void;
  onChangeType?: (type: string) => void;
}

// How the object was found, so that the analyst can judge it without opening it (US.4).
export const useStatusText = (item: ReviewItem, occurrences: number, sourceLabel: (source: string) => string) => {
  const { t_i18n } = useFormatter();
  const parts: string[] = [];
  if (item.entity) {
    parts.push(t_i18n('Existing'));
    if (item.resolvedFrom) parts.push(`« ${item.resolvedFrom} » ${t_i18n('resolved')}`);
  } else {
    parts.push(t_i18n('New'));
    if (isDefanged(item.value)) parts.push(t_i18n('auto refang'));
    const algorithm = item.entityType === 'StixFile' ? hashAlgorithmOf(refangValue(item.value)) : null;
    if (algorithm) parts.push(`hashes.${algorithm} ${t_i18n('prefilled')}`);
  }
  // Ignored values are not highlighted, so they are not counted.
  if (occurrences > 0) parts.push(`${occurrences} ${t_i18n(occurrences > 1 ? 'occurrences' : 'occurrence')}`);
  if (item.source !== MAIN_CONTENT_SOURCE) parts.push(sourceLabel(item.source));
  return parts.join(' · ');
};

const RowAction = ({ label, icon, onClick }: { label: string; icon: ReactNode; onClick: () => void }) => (
  <Tooltip>
    <TooltipTrigger asChild>
      <IconButton
        size="sm"
        priority="tertiary"
        aria-label={label}
        icon={icon}
        onClick={(event) => {
          event.stopPropagation();
          onClick();
        }}
      />
    </TooltipTrigger>
    <TooltipContent>{label}</TooltipContent>
  </Tooltip>
);

const MappingRow = ({
  item, occurrences, selected, active, sourceLabel, onToggle, onHover, onAccept, onReject, onRestore, onUnmap, onChangeType,
}: MappingRowProps) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const statusText = useStatusText(item, occurrences, sourceLabel);
  const isDuplicate = item.duplicateTypes.length > 0;
  const otherTypes = onChangeType && !item.entity
    ? typeCandidates(item.value).filter((c) => c.compatible && canCreateType(c.type) && c.type !== item.entityType)
    : [];
  const displayedValue = item.entity?.representative?.main ?? refangValue(item.value);

  return (
    <Box
      onMouseEnter={() => onHover(true)}
      onMouseLeave={() => onHover(false)}
      onClick={onToggle}
      data-testid={`mapping-row-${item.key}`}
      sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 1.25,
        minHeight: 56,
        paddingRight: 1,
        borderRadius: '4px',
        cursor: 'pointer',
        border: `1px solid ${active ? theme.palette.primary.main : (isDuplicate ? alpha(theme.palette.warning.main, 0.8) : 'transparent')}`,
        backgroundColor: active ? alpha(theme.palette.primary.main, 0.08) : theme.palette.background.default,
      }}
    >
      <Box sx={{ width: 3, alignSelf: 'stretch', margin: '8px 0', borderRadius: '2px', backgroundColor: itemColor(item.entityType) }} />
      <Checkbox
        checked={selected}
        onCheckedChange={onToggle}
        onClick={(event) => event.stopPropagation()}
        aria-label={`${t_i18n('Select')} ${displayedValue}`}
      />
      <Box sx={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 0.5, padding: '6px 0' }}>
        <Box sx={{ fontWeight: 600, fontSize: 13, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{displayedValue}</Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, fontSize: 11, color: theme.palette.text.secondary, minWidth: 0 }}>
          <ItemEntityType entityType={item.entityType} />
          {isDuplicate ? (
            <Box component="span" sx={{ display: 'inline-flex', alignItems: 'center', gap: 0.5, color: theme.palette.warning.main, whiteSpace: 'nowrap' }}>
              <WarningAmberOutlined sx={{ fontSize: 14 }} />
              {t_i18n('Possible duplicate: also exists as')} {item.duplicateTypes.map((type) => t_i18n(`entity_${type}`)).join(', ')}
            </Box>
          ) : (
            <Box component="span" sx={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{statusText}</Box>
          )}
        </Box>
      </Box>
      {otherTypes.length > 0 && (
        <Menu>
          <MenuTrigger asChild>
            <IconButton size="sm" priority="tertiary" aria-label={t_i18n('Change the type')} icon={<SwapHorizOutlined fontSize="small" />} onClick={(event) => event.stopPropagation()} />
          </MenuTrigger>
          <MenuContent align="end">
            {otherTypes.map(({ type }) => (
              <MenuItem key={type} onSelect={() => onChangeType?.(type)}>
                <ItemEntityType entityType={type} />
              </MenuItem>
            ))}
          </MenuContent>
        </Menu>
      )}
      {onAccept && <RowAction label={item.entity ? t_i18n('Map') : t_i18n('Create and map')} icon={<CheckOutlined fontSize="small" color="success" />} onClick={onAccept} />}
      {onReject && <RowAction label={t_i18n('Ignore')} icon={<CloseOutlined fontSize="small" />} onClick={onReject} />}
      {onRestore && <RowAction label={t_i18n('Restore')} icon={<RestoreOutlined fontSize="small" />} onClick={onRestore} />}
      {onUnmap && <RowAction label={t_i18n('Remove the mapping')} icon={<CloseOutlined fontSize="small" />} onClick={onUnmap} />}
    </Box>
  );
};

export default MappingRow;
