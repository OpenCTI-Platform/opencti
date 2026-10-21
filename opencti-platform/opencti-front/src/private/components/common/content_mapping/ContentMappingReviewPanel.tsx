import React, { useMemo, useState } from 'react';
import { Box } from '@mui/material';
import { alpha, useTheme } from '@mui/material/styles';
import { Checkbox, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Tabs, TabsList, TabsTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import Tag from '@common/tag/Tag';
import { useFormatter } from '../../../../components/i18n';
import ItemEntityType from '../../../../components/ItemEntityType';
import { familyOf, filterReviewItems, ReviewFamily, ReviewFilter, ReviewItem, ReviewSort, ReviewStatus, sortReviewItems } from './contentMappingModel';
import MappingRow from './MappingRow';
import MappingEnrichmentDialog from './MappingEnrichmentDialog';
import type { EnrichmentValues } from './useContentMappingActions';

export type ReviewTab = ReviewStatus | 'relations';

export interface RelationItem {
  id: string;
  relationshipType: string;
  description: string | null;
  from: { id: string; entityType: string; name: string; key: string | null };
  to: { id: string; entityType: string; name: string; key: string | null };
}

interface ContentMappingReviewPanelProps {
  items: ReviewItem[];
  counts: Record<string, number>;
  relations: RelationItem[];
  tab: ReviewTab;
  onTabChange: (tab: ReviewTab) => void;
  selectedKeys: string[];
  onSelectedKeysChange: (keys: string[]) => void;
  activeKey: string | null;
  onActiveKeyChange: (key: string | null) => void;
  sourceLabel: (source: string) => string;
  analysisPending: boolean;
  onValidate: (items: ReviewItem[], enrichment?: EnrichmentValues) => void;
  onIgnore: (items: ReviewItem[]) => void;
  onRestore: (keys: string[]) => void;
  onUnmap: (keys: string[]) => void;
  onChangeType: (key: string, type: string) => void;
  onCreateRelation: () => void;
  onActiveRelationChange: (relation: RelationItem | null) => void;
}

const FAMILIES: (ReviewFamily | 'all')[] = ['all', 'entities', 'observables', 'ttp'];
const FAMILY_COLORS: Record<ReviewFamily, string> = { entities: '#FF9800', observables: '#42a5f5', ttp: '#26c6da' };

const ContentMappingReviewPanel = ({
  items, counts, relations, tab, onTabChange, selectedKeys, onSelectedKeysChange, activeKey, onActiveKeyChange, sourceLabel,
  analysisPending, onValidate, onIgnore, onRestore, onUnmap, onChangeType, onCreateRelation, onActiveRelationChange,
}: ContentMappingReviewPanelProps) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const [filter, setFilter] = useState<ReviewFilter>({ family: 'all', duplicatesOnly: false });
  const [sort, setSort] = useState<ReviewSort>('status');
  const [enrichOpen, setEnrichOpen] = useState(false);

  const status = tab === 'relations' ? null : tab;
  const tabItems = useMemo(() => (status ? sortReviewItems(filterReviewItems(items, status, filter), sort) : []), [items, status, filter, sort]);
  const countOf = (s: ReviewStatus) => items.filter((item) => item.status === s).length;
  const statusItems = status ? items.filter((item) => item.status === status) : [];
  const selectedItems = tabItems.filter((item) => selectedKeys.includes(item.key));
  const toggle = (key: string) => onSelectedKeysChange(selectedKeys.includes(key) ? selectedKeys.filter((k) => k !== key) : [...selectedKeys, key]);
  const allSelected = tabItems.length > 0 && tabItems.every((item) => selectedKeys.includes(item.key));

  const familyLabel = (family: ReviewFamily | 'all') => {
    if (family === 'all') return t_i18n('All');
    const label = { entities: t_i18n('Entities'), observables: t_i18n('Observables'), ttp: t_i18n('TTP') }[family];
    return `${label} ${statusItems.filter((item) => familyOf(item.entityType) === family).length}`;
  };
  const duplicates = statusItems.filter((item) => item.duplicateTypes.length > 0).length;

  return (
    <Box sx={{ width: 460, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 1.25, minHeight: 0 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <Box sx={{ fontWeight: 600, fontSize: 15 }}>{t_i18n('Detected objects')}</Box>
        <Box sx={{ fontFamily: 'monospace', fontSize: 12, color: theme.palette.text.secondary }}>{items.length}</Box>
        <Box sx={{ marginLeft: 'auto', width: 170 }}>
          <Select value={sort} onValueChange={(value) => setSort(value as ReviewSort)}>
            <SelectTrigger aria-label={t_i18n('Sort by')}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="status">{t_i18n('Sort: new first')}</SelectItem>
              <SelectItem value="type">{t_i18n('Sort: type')}</SelectItem>
              <SelectItem value="value">{t_i18n('Sort: value')}</SelectItem>
            </SelectContent>
          </Select>
        </Box>
      </Box>
      <Tabs
        value={tab}
        onValueChange={(value) => {
          onTabChange(value as ReviewTab);
          onSelectedKeysChange([]);
        }}
      >
        <TabsList>
          <TabsTrigger value="toReview">{`${t_i18n('To review')} · ${countOf('toReview')}`}</TabsTrigger>
          <TabsTrigger value="mapped">{`${t_i18n('Mapped')} · ${countOf('mapped')}`}</TabsTrigger>
          <TabsTrigger value="ignored">{`${t_i18n('Ignored')} · ${countOf('ignored')}`}</TabsTrigger>
          <TabsTrigger value="relations">{`${t_i18n('Relations')} · ${relations.length}`}</TabsTrigger>
        </TabsList>
      </Tabs>
      {status && (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.75 }}>
          {FAMILIES.map((family) => (
            <Tag
              key={family}
              label={familyLabel(family)}
              color={filter.family === family ? (family === 'all' ? theme.palette.primary.main : FAMILY_COLORS[family]) : theme.palette.text.disabled}
              onClick={() => setFilter({ ...filter, family })}
            />
          ))}
          {duplicates > 0 && (
            <Tag
              label={`⚠ ${duplicates}`}
              color={filter.duplicatesOnly ? theme.palette.warning.main : theme.palette.text.disabled}
              tooltipTitle={t_i18n('Possible duplicates')}
              onClick={() => setFilter({ ...filter, duplicatesOnly: !filter.duplicatesOnly })}
            />
          )}
        </Box>
      )}
      {status && tabItems.length > 0 && (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, padding: '6px 10px', borderRadius: '4px', backgroundColor: alpha(theme.palette.primary.main, 0.08), minHeight: 47 }}>
          <Checkbox
            checked={allSelected}
            onCheckedChange={() => onSelectedKeysChange(allSelected ? [] : tabItems.map((item) => item.key))}
            aria-label={t_i18n('Select all')}
          />
          <Box sx={{ fontSize: 12, fontWeight: 600, color: theme.palette.primary.main }}>
            {selectedItems.length > 0 ? `${selectedItems.length} ${t_i18n('selected')}` : t_i18n('Select all')}
          </Box>
          <Box sx={{ marginLeft: 'auto', display: 'flex', gap: 1 }}>
            {status === 'toReview' && selectedItems.length > 0 && (
              <>
                <Button variant="tertiary" size="small" onClick={() => onIgnore(selectedItems)}>{t_i18n('Ignore')}</Button>
                <Button variant="secondary" size="small" onClick={() => setEnrichOpen(true)}>{t_i18n('Markings · Labels · Confidence')}</Button>
                <Button size="small" onClick={() => onValidate(selectedItems)}>{t_i18n('Validate')}</Button>
              </>
            )}
            {status === 'mapped' && selectedItems.length === 2 && (
              <Button size="small" onClick={onCreateRelation}>{t_i18n('Create a relationship')}</Button>
            )}
            {status === 'mapped' && selectedItems.length > 0 && (
              <Button variant="tertiary" size="small" onClick={() => onUnmap(selectedItems.map((item) => item.key))}>{t_i18n('Remove the mapping')}</Button>
            )}
            {status === 'ignored' && selectedItems.length > 0 && (
              <Button size="small" onClick={() => onRestore(selectedItems.map((item) => item.key))}>{t_i18n('Restore')}</Button>
            )}
          </Box>
        </Box>
      )}
      <Box sx={{ flex: 1, minHeight: 0, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 0.75 }}>
        {status && tabItems.map((item) => (
          <MappingRow
            key={item.key}
            item={item}
            occurrences={counts[item.key] ?? 0}
            selected={selectedKeys.includes(item.key)}
            active={activeKey === item.key}
            sourceLabel={sourceLabel}
            onToggle={() => toggle(item.key)}
            onHover={(hovered) => onActiveKeyChange(hovered ? item.key : null)}
            onAccept={status === 'toReview' ? () => onValidate([item]) : undefined}
            onReject={status === 'toReview' ? () => onIgnore([item]) : undefined}
            onRestore={status === 'ignored' ? () => onRestore([item.key]) : undefined}
            onUnmap={status === 'mapped' ? () => onUnmap([item.key]) : undefined}
            onChangeType={status === 'toReview' ? (type) => onChangeType(item.key, type) : undefined}
          />
        ))}
        {status && tabItems.length === 0 && (
          <Box sx={{ padding: 2, fontSize: 12, color: theme.palette.text.secondary }}>
            {status === 'toReview' && (analysisPending ? t_i18n('Analysis in progress…') : t_i18n('Nothing to review: ask for an AI mapping, or highlight some text to map it.'))}
            {status === 'mapped' && t_i18n('No mapped object yet.')}
            {status === 'ignored' && t_i18n('No ignored suggestion.')}
          </Box>
        )}
        {tab === 'relations' && relations.map((relation) => (
          <Box
            key={relation.id}
            onMouseEnter={() => onActiveRelationChange(relation)}
            onMouseLeave={() => onActiveRelationChange(null)}
            sx={{ display: 'flex', flexDirection: 'column', gap: 0.75, padding: '10px 12px', borderRadius: '6px', border: `1px solid ${theme.palette.divider}` }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, flexWrap: 'wrap', fontSize: 12 }}>
              <ItemEntityType entityType={relation.from.entityType} />
              <strong>{relation.from.name}</strong>
              <Box component="span" sx={{ fontFamily: 'monospace', color: theme.palette.primary.main }}>{`${t_i18n(`relationship_${relation.relationshipType}`)} →`}</Box>
              <ItemEntityType entityType={relation.to.entityType} />
              <strong>{relation.to.name}</strong>
            </Box>
            {relation.description && <Box sx={{ fontSize: 11, color: theme.palette.text.secondary }}>{relation.description}</Box>}
          </Box>
        ))}
        {tab === 'relations' && relations.length === 0 && (
          <Box sx={{ padding: 2, fontSize: 12, color: theme.palette.text.secondary }}>
            {t_i18n('Select two mapped objects, in the text or in the Mapped tab, to create a relationship between them.')}
          </Box>
        )}
      </Box>
      <Box sx={{ fontSize: 11, color: theme.palette.text.secondary }}>
        {t_i18n('AI suggestions are never validated automatically. Hovering a row highlights its passages in the text.')}
      </Box>
      <MappingEnrichmentDialog
        open={enrichOpen}
        count={selectedItems.length}
        onClose={() => setEnrichOpen(false)}
        onSubmit={(enrichment) => onValidate(selectedItems, enrichment)}
      />
    </Box>
  );
};

export default ContentMappingReviewPanel;
