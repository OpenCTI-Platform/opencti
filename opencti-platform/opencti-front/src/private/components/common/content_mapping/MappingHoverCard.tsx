import React from 'react';
import { Link } from 'react-router';
import { Box, Popper } from '@mui/material';
import { alpha, useTheme } from '@mui/material/styles';
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import ItemEntityType from '../../../../components/ItemEntityType';
import { resolveLink } from '../../../../utils/Entity';
import { ReviewItem } from './contentMappingModel';
import { refangValue, typeCandidates } from './mappingValue';
import { canCreateType } from './useContentMappingActions';
import { useStatusText } from './MappingRow';

interface MappingHoverCardProps {
  item: ReviewItem | null;
  anchorRect: DOMRect | null;
  occurrences: number;
  sourceLabel: (source: string) => string;
  onKeepOpen: (open: boolean) => void;
  onValidate: (item: ReviewItem) => void;
  onIgnore: (item: ReviewItem) => void;
  onRestore: (item: ReviewItem) => void;
  onUnmap: (item: ReviewItem) => void;
  onChangeType: (item: ReviewItem, type: string) => void;
}

// Shown on hover of a highlighted value: what it is, and the actions on it, without leaving the text.
const MappingHoverCard = ({
  item, anchorRect, occurrences, sourceLabel, onKeepOpen, onValidate, onIgnore, onRestore, onUnmap, onChangeType,
}: MappingHoverCardProps) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const statusText = useStatusText(item ?? ({ duplicateTypes: [], value: '', source: 'main' } as unknown as ReviewItem), occurrences, sourceLabel);
  if (!item || !anchorRect) return null;
  const otherTypes = !item.entity ? typeCandidates(item.value).filter((c) => c.compatible && canCreateType(c.type) && c.type !== item.entityType) : [];
  const virtualAnchor = { getBoundingClientRect: () => anchorRect };

  return (
    <Popper open anchorEl={virtualAnchor} placement="bottom-start" style={{ zIndex: theme.zIndex.modal }}>
      <Box
        onMouseEnter={() => onKeepOpen(true)}
        onMouseLeave={() => onKeepOpen(false)}
        sx={{
          marginTop: 1,
          padding: '10px 12px',
          display: 'flex',
          flexDirection: 'column',
          gap: 0.75,
          borderRadius: '6px',
          border: `1px solid ${theme.palette.primary.main}`,
          backgroundColor: theme.palette.background.paper,
          boxShadow: `0 6px 16px ${alpha('#000', 0.5)}`,
          maxWidth: 360,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <ItemEntityType entityType={item.entityType} />
          <Box sx={{ fontFamily: 'monospace', fontWeight: 600, fontSize: 13 }}>{item.entity?.representative?.main ?? refangValue(item.value)}</Box>
        </Box>
        <Box sx={{ fontSize: 11, color: theme.palette.text.secondary }}>
          {item.status === 'mapped' ? `${t_i18n('Mapped')} · ${statusText}` : statusText}
        </Box>
        {item.duplicateTypes.length > 0 && (
          <Box sx={{ fontSize: 11, color: theme.palette.warning.main }}>
            {`⚠ ${t_i18n('Possible duplicate: also exists as')} ${item.duplicateTypes.map((type) => t_i18n(`entity_${type}`)).join(', ')}`}
          </Box>
        )}
        <Box sx={{ display: 'flex', gap: 0.75, flexWrap: 'wrap' }}>
          {item.status === 'toReview' && (
            <>
              <Button size="small" onClick={() => onValidate(item)}>{item.entity ? t_i18n('Map') : t_i18n('Create')}</Button>
              {otherTypes.length > 0 && (
                <Menu>
                  <MenuTrigger asChild>
                    <Button variant="tertiary" size="small">{t_i18n('Change the type')}</Button>
                  </MenuTrigger>
                  <MenuContent align="start">
                    {otherTypes.map(({ type }) => (
                      <MenuItem key={type} onSelect={() => onChangeType(item, type)}>
                        <ItemEntityType entityType={type} />
                      </MenuItem>
                    ))}
                  </MenuContent>
                </Menu>
              )}
              <Button variant="tertiary" size="small" onClick={() => onIgnore(item)}>{t_i18n('Ignore')}</Button>
            </>
          )}
          {item.status === 'mapped' && (
            <>
              {item.entity && (
                <Button variant="secondary" size="small" component={Link} to={`${resolveLink(item.entity.entity_type)}/${item.entity.id}`}>
                  {t_i18n('Open')}
                </Button>
              )}
              <Button variant="tertiary" size="small" onClick={() => onUnmap(item)}>{t_i18n('Remove the mapping')}</Button>
            </>
          )}
          {item.status === 'ignored' && (
            <Button variant="secondary" size="small" onClick={() => onRestore(item)}>{t_i18n('Restore')}</Button>
          )}
        </Box>
      </Box>
    </Popper>
  );
};

export default MappingHoverCard;
