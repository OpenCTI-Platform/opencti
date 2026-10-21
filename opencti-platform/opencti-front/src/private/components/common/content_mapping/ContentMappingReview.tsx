import React, { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useLazyLoadQuery } from 'react-relay';
import { Box } from '@mui/material';
import { alpha, useTheme } from '@mui/material/styles';
import { Checkbox, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Switch } from '@filigran/design-system';
import { AutoAwesomeOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import Tag from '@common/tag/Tag';
import StixCoreRelationshipCreation from '@components/common/stix_core_relationships/StixCoreRelationshipCreation';
import { useFormatter } from '../../../../components/i18n';
import ItemEntityType from '../../../../components/ItemEntityType';
import { commitMutation, fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { itemColor } from '../../../../utils/Colors';
import { convertCreatedBy, convertMarkings } from '../../../../utils/edition';
import useDraftContext, { DRAFT_TOOLBAR_HEIGHT } from '../../../../utils/hooks/useDraftContext';
import { minutesBefore, now } from '../../../../utils/Time';
import {
  contentMappingAnalysisQuery,
  contentMappingDuplicatesQuery,
  contentMappingRelationsAddMutation,
  contentMappingRelationshipDescriptionMutation,
  contentMappingReviewQuery,
} from './contentMappingQueries';
import { contentMappingQueriesReviewQuery, contentMappingQueriesReviewQuery$data } from './__generated__/contentMappingQueriesReviewQuery.graphql';
import { contentMappingQueriesAnalysisQuery, contentMappingQueriesAnalysisQuery$data } from './__generated__/contentMappingQueriesAnalysisQuery.graphql';
import { contentMappingQueriesDuplicatesQuery$data } from './__generated__/contentMappingQueriesDuplicatesQuery.graphql';
import { AnalysisSuggestions, buildReviewItems, decodeMapping, decodeReview, MAIN_CONTENT_SOURCE, MappableEntity, mappingKey, ReviewItem } from './contentMappingModel';
import { HighlightTerm } from './highlight';
import ContentMappingDocument, { MappingSource, sourceKindOf, TextSelection } from './ContentMappingDocument';
import ContentMappingReviewPanel, { RelationItem, ReviewTab } from './ContentMappingReviewPanel';
import MappingSelectionPopover from './MappingSelectionPopover';
import MappingHoverCard from './MappingHoverCard';
import useContentMappingActions from './useContentMappingActions';

type Container = NonNullable<contentMappingQueriesReviewQuery$data['container']>;

const EMPTY_SUGGESTIONS: AnalysisSuggestions = { mapped: [], unresolved: [] };
const ANALYSIS_POLLING_MS = 3000;

// The sentence of the document that mentions both objects: the evidence of their relationship.
const findPassage = (text: string, a: string, b: string) => text
  .split(/(?<=[.!?])\s+/)
  .find((sentence) => sentence.toLowerCase().includes(a.toLowerCase()) && sentence.toLowerCase().includes(b.toLowerCase()))
  ?.trim() ?? null;

const useAnalysis = (containerId: string, source: MappingSource) => {
  const [analysis, setAnalysis] = useState<{ status: string | null; suggestions: AnalysisSuggestions; hasConnector: boolean }>({
    status: null, suggestions: EMPTY_SUGGESTIONS, hasConnector: false,
  });
  const [pollKey, setPollKey] = useState(0);
  const variables = source.kind === 'main'
    ? { id: containerId, contentSource: 'content_mapping', contentType: 'fields' as const }
    : { id: containerId, contentSource: source.id, contentType: 'file' as const };

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    let cancelled = false;
    const load = () => fetchQuery<contentMappingQueriesAnalysisQuery>(contentMappingAnalysisQuery, variables, { fetchPolicy: 'network-only' })
      .toPromise()
      .then((data) => {
        if (cancelled) return;
        const result = data as contentMappingQueriesAnalysisQuery$data | undefined;
        const mappingAnalysis = result?.stixCoreObjectAnalysis;
        const status = mappingAnalysis?.analysisStatus ?? null;
        setAnalysis({
          status,
          hasConnector: (result?.connectorsForAnalysis ?? []).length > 0,
          suggestions: {
            mapped: (mappingAnalysis?.mappedEntities ?? []) as AnalysisSuggestions['mapped'],
            unresolved: mappingAnalysis?.unresolvedEntities ?? [],
          },
        });
        if (status && status !== 'complete') timer = setTimeout(load, ANALYSIS_POLLING_MS);
      });
    load();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [containerId, source.id, pollKey]);

  return { analysis, reloadAnalysis: () => setPollKey((k) => k + 1), analysisVariables: variables };
};

// The document and the panel scroll on their own, so that long reports stay readable (#18925): the view
// takes the height left below it in the window.
const useRemainingHeight = (bottomOffset: number) => {
  const ref = useRef<HTMLDivElement>(null);
  const [height, setHeight] = useState(600);
  useLayoutEffect(() => {
    const update = () => {
      const top = ref.current?.getBoundingClientRect().top ?? 0;
      setHeight(Math.max(480, window.innerHeight - top - bottomOffset - 24));
    };
    update();
    window.addEventListener('resize', update);
    return () => window.removeEventListener('resize', update);
  }, [bottomOffset]);
  return { ref, height };
};

const ContentMappingReview = ({ containerId }: { containerId: string }) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  // In a Draft, the draft toolbar takes the bottom of the window.
  const layout = useRemainingHeight(draftContext ? DRAFT_TOOLBAR_HEIGHT : 0);
  const { container } = useLazyLoadQuery<contentMappingQueriesReviewQuery>(contentMappingReviewQuery, { id: containerId }, { fetchPolicy: 'store-and-network' });
  const refresh = useCallback(() => {
    fetchQuery(contentMappingReviewQuery, { id: containerId }, { fetchPolicy: 'network-only' }).toPromise();
  }, [containerId]);

  // Sources: the description and content of the container, and its attached files that can be read (#17785, #8909).
  const sources = useMemo<MappingSource[]>(() => [
    { id: MAIN_CONTENT_SOURCE, label: t_i18n('Description & main content'), kind: 'main' },
    // A file still being uploaded comes without node: it is listed once stored.
    ...(container?.importFiles?.edges ?? []).flatMap((edge) => {
      const file = edge?.node;
      const kind = sourceKindOf(file?.metaData?.mimetype);
      return file && kind ? [{ id: file.id, label: file.name, kind }] : [];
    }),
  ], [container?.importFiles]);
  const [sourceId, setSourceId] = useState(MAIN_CONTENT_SOURCE);
  const source = sources.find((s) => s.id === sourceId) ?? sources[0];
  const sourceLabel = useCallback((id: string) => sources.find((s) => s.id === id)?.label ?? id, [sources]);

  const { analysis, reloadAnalysis, analysisVariables } = useAnalysis(containerId, source);
  const [showSuggestions, setShowSuggestions] = useState(true);
  const [tab, setTab] = useState<ReviewTab>('toReview');
  const [selectedKeys, setSelectedKeys] = useState<string[]>([]);
  const [activeKeys, setActiveKeys] = useState<string[]>([]);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [documentText, setDocumentText] = useState('');
  const [selection, setSelection] = useState<TextSelection | null>(null);
  const [hover, setHover] = useState<{ key: string; rect: DOMRect } | null>(null);
  const hoverCardOpen = useRef(false);
  const [relationDialog, setRelationDialog] = useState<{ from: ReviewItem; to: ReviewItem; passage: string | null } | null>(null);
  const [relationDialogOpen, setRelationDialogOpen] = useState(false);
  const [linkEvidence, setLinkEvidence] = useState(true);
  const [existingTypesByName, setExistingTypesByName] = useState<Record<string, string[]>>({});
  const [activeRelation, setActiveRelation] = useState<RelationItem | null>(null);
  const mapping = useMemo(() => decodeMapping(container?.content_mapping), [container?.content_mapping]);
  const review = useMemo(() => decodeReview(container?.content_mapping_review), [container?.content_mapping_review]);
  const objects = useMemo(() => (container?.objects?.edges ?? [])
    .flatMap((edge) => (edge?.node?.standard_id ? [edge.node as MappableEntity & { relationship_type?: string }] : [])), [container?.objects]);
  const objectIds = useMemo(() => new Set(objects.map((o) => o.id)), [objects]);

  const items = useMemo(() => buildReviewItems({
    mapping, review, objects, suggestions: analysis.suggestions, suggestionSource: source.id, existingTypesByName,
  }), [mapping, review, objects, analysis.suggestions, source.id, existingTypesByName]);
  const itemsByKey = useMemo(() => new Map(items.map((item) => [item.key, item])), [items]);

  // Possible duplicates: names to create that already exist in the platform, under any type.
  const namesToCreate = items.filter((item) => item.status === 'toReview' && !item.entity).map((item) => item.value);
  useEffect(() => {
    if (namesToCreate.length === 0) return;
    fetchQuery(contentMappingDuplicatesQuery, {
      filters: { mode: 'or', filterGroups: [], filters: [{ key: ['name', 'aliases', 'x_opencti_aliases'], values: namesToCreate, operator: 'eq', mode: 'or' }] },
    }).toPromise().then((data) => {
      const found: Record<string, string[]> = {};
      ((data as contentMappingQueriesDuplicatesQuery$data)?.stixCoreObjects?.edges ?? []).forEach((edge) => {
        const name = mappingKey(edge?.node.representative?.main ?? '');
        if (name && edge) found[name] = [...new Set([...(found[name] ?? []), edge.node.entity_type])];
      });
      setExistingTypesByName(found);
    });
  }, [namesToCreate.join('|')]);

  const terms = useMemo<HighlightTerm[]>(() => items
    .filter((item) => item.status === 'mapped' || (showSuggestions && item.status === 'toReview'))
    .map((item) => ({
      key: item.key,
      text: item.value,
      color: itemColor(item.entityType),
      status: (item.status === 'mapped' && 'mapped') || (item.entity ? 'suggested' : 'new'),
    })), [items, showSuggestions]);

  const actions = useContentMappingActions({
    id: containerId,
    objectIds,
    mapping,
    review,
    serverVersion: `${container?.content_mapping ?? ''}|${container?.content_mapping_review ?? ''}`,
    createdById: container?.createdBy?.id,
  }, refresh);

  const notifyWithUndo = (message: string, undo: () => Promise<void>) => {
    MESSAGING$.notifySuccess(
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 12 }}>
        {message}
        <Button variant="tertiary" size="small" onClick={() => undo()}>{t_i18n('Undo')}</Button>
      </span>,
    );
  };

  const run = async (action: () => Promise<unknown>) => {
    try {
      await action();
    } catch {
      // Errors are already displayed by the mutation handler.
    }
  };

  const handleMapExisting = (value: string, entity: MappableEntity) => run(async () => {
    const undo = await actions.mapExisting(value, entity, source.id);
    notifyWithUndo(`✓ ${t_i18n(`entity_${entity.entity_type}`)} ${t_i18n('mapped')}`, undo);
  });
  const handleCreate = (value: string, type: string) => run(async () => {
    const { undo } = await actions.createAndMap(value, type, source.id);
    notifyWithUndo(`✓ ${t_i18n(`entity_${type}`)} ${t_i18n('created and mapped')}`, undo);
  });
  const handleValidate = (toValidate: ReviewItem[], enrichment?: Parameters<typeof actions.validate>[1]) => run(async () => {
    const count = await actions.validate(toValidate, enrichment);
    setSelectedKeys([]);
    MESSAGING$.notifySuccess(`${count} ${t_i18n(count > 1 ? 'objects mapped' : 'object mapped')}`);
  });
  const handleIgnore = (toIgnore: ReviewItem[]) => run(async () => {
    await actions.ignore(toIgnore);
    setSelectedKeys([]);
  });

  // Mapped objects selected in the text or in the Mapped tab, for a relationship (US.8).
  const relationCandidates = tab === 'mapped' ? selectedKeys.map((key) => itemsByKey.get(key)).filter((item): item is ReviewItem => !!item?.entity) : [];
  const handleClickKey = (key: string) => {
    if (itemsByKey.get(key)?.status !== 'mapped') return;
    setTab('mapped');
    setSelectedKeys((keys) => {
      const current = tab === 'mapped' ? keys : [];
      return current.includes(key) ? current.filter((k) => k !== key) : [...current, key].slice(-2);
    });
  };
  const openRelationDialog = () => {
    const [from, to] = relationCandidates;
    if (from && to) {
      setRelationDialog({ from, to, passage: findPassage(documentText, from.value, to.value) });
      setRelationDialogOpen(true);
    }
  };
  const handleRelationCreated = (relation: { id?: string } | null | undefined) => run(async () => {
    if (!relation?.id) return;
    await new Promise((resolve, reject) => commitMutation({
      mutation: contentMappingRelationsAddMutation,
      variables: { id: containerId, toIds: [relation.id] },
      onCompleted: resolve,
      onError: reject,
    }));
    if (linkEvidence && relationDialog?.passage) {
      await new Promise((resolve, reject) => commitMutation({
        mutation: contentMappingRelationshipDescriptionMutation,
        variables: { id: relation.id, input: [{ key: 'description', value: [`« ${relationDialog.passage} »`] }] },
        onCompleted: resolve,
        onError: reject,
      }));
    }
    setSelectedKeys([]);
    setTab('relations');
    refresh();
  });

  const entityKeyById = useMemo(() => new Map(items.filter((item) => item.status === 'mapped' && item.entity).map((item) => [item.entity!.id, item.key])), [items]);
  const relations = useMemo<RelationItem[]>(() => (container?.objects?.edges ?? []).flatMap((edge) => {
    const node = edge?.node;
    if (!node?.relationship_type || !node.from?.id || !node.to?.id) return [];
    if (!entityKeyById.has(node.from.id) && !entityKeyById.has(node.to.id)) return [];
    const end = (e: NonNullable<typeof node.from>) => ({ id: e.id!, entityType: e.entity_type!, name: e.representative?.main ?? '', key: entityKeyById.get(e.id!) ?? null });
    return [{ id: node.id!, relationshipType: node.relationship_type, description: node.description ?? null, from: end(node.from), to: end(node.to) }];
  }), [container?.objects, entityKeyById]);

  // Stable references: the relationship dialog reloads the existing relationships when they change.
  const relationEnds = useMemo(() => {
    const toGraphNode = (item: ReviewItem) => ({ id: item.entity!.id, entity_type: item.entity!.entity_type, name: item.entity!.representative?.main ?? item.value }) as never;
    return relationDialog ? { from: [toGraphNode(relationDialog.from)], to: [toGraphNode(relationDialog.to)] } : { from: [], to: [] };
  }, [relationDialog]);

  if (!container) return null;
  const hoveredItem = hover ? itemsByKey.get(hover.key) ?? null : null;
  const analysisPending = !!analysis.status && analysis.status !== 'complete';
  const highlightedKeys = activeRelation
    ? [activeRelation.from.key, activeRelation.to.key].filter((k): k is string => !!k)
    : activeKeys;

  const legend = (label: string, style: 'solid' | 'dashed' | 'wavy') => (
    <Box component="span" sx={{ textDecorationLine: 'underline', textDecorationStyle: style, textDecorationThickness: '2px', textUnderlineOffset: '3px', fontWeight: 500 }}>{label}</Box>
  );

  return (
    <Box ref={layout.ref} sx={{ display: 'flex', gap: 2, height: layout.height }}>
      <Box sx={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 1.75, padding: '18px 24px', borderRadius: '6px', border: `1px solid ${theme.palette.divider}`, backgroundColor: theme.palette.background.paper }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, flexWrap: 'wrap', fontSize: 12 }}>
          <Box sx={{ width: 260 }}>
            <Select
              value={source.id}
              onValueChange={(value) => {
                setSourceId(value);
                setSelectedKeys([]);
              }}
            >
              <SelectTrigger aria-label={t_i18n('Source')}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {sources.map((s) => <SelectItem key={s.id} value={s.id}>{s.label}</SelectItem>)}
              </SelectContent>
            </Select>
          </Box>
          {legend(t_i18n('Validated'), 'solid')}
          {legend(t_i18n('Suggested by AI'), 'dashed')}
          {legend(t_i18n('New (to create)'), 'wavy')}
          {draftContext && (
            <Tag label={t_i18n('Draft')} color={theme.palette.warning.main} tooltipTitle={`${draftContext.name} · ${t_i18n('Mapped and created objects stay in the draft until it is validated.')}`} />
          )}
          <Box sx={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 1.5 }}>
            <Switch checked={showSuggestions} onCheckedChange={setShowSuggestions} label={t_i18n('Suggestions visible')} />
            <Button
              variant="secondary"
              size="small"
              startIcon={<AutoAwesomeOutlined fontSize="small" />}
              disabled={!analysis.hasConnector || analysisPending}
              onClick={() => run(async () => {
                await actions.askAnalysis(analysisVariables.contentSource, analysisVariables.contentType);
                reloadAnalysis();
              })}
            >
              {analysisPending ? t_i18n('Analysis in progress…') : t_i18n('Ask for an AI mapping')}
            </Button>
          </Box>
        </Box>
        {activeRelation?.description && (
          <Box sx={{ display: 'flex', gap: 1, padding: '8px 12px', borderRadius: '4px', fontSize: 12, border: `1px solid ${alpha(theme.palette.primary.main, 0.4)}`, backgroundColor: alpha(theme.palette.primary.main, 0.08) }}>
            <Box sx={{ width: 3, borderRadius: '2px', backgroundColor: theme.palette.primary.main }} />
            {`${t_i18n('Source passage of the hovered relationship')}: ${activeRelation.description}`}
          </Box>
        )}
        {relationCandidates.length === 2 && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.25, flexWrap: 'wrap', padding: '8px 8px 8px 14px', borderRadius: '8px', border: `1px solid ${alpha(theme.palette.primary.main, 0.7)}`, backgroundColor: theme.palette.background.default }}>
            <Box sx={{ fontWeight: 600, fontSize: 12 }}>{t_i18n('2 entities selected')}</Box>
            {relationCandidates.map((item, index) => (
              <React.Fragment key={item.key}>
                {index > 0 && <span style={{ color: theme.palette.text.disabled }}>+</span>}
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, padding: '2px 8px', borderRadius: '4px', border: `1.5px solid ${itemColor(item.entityType)}` }}>
                  <strong style={{ fontSize: 12 }}>{item.entity?.representative?.main ?? item.value}</strong>
                  <ItemEntityType entityType={item.entityType} />
                </Box>
              </React.Fragment>
            ))}
            <Checkbox
              checked={linkEvidence}
              onCheckedChange={(checked) => setLinkEvidence(checked === true)}
              label={t_i18n('Link the source passage as evidence')}
            />
            <Box sx={{ marginLeft: 'auto' }}>
              <Button size="small" onClick={openRelationDialog}>{t_i18n('Create a relationship')}</Button>
            </Box>
          </Box>
        )}
        <ContentMappingDocument
          source={source}
          title={source.kind === 'main' ? container.name : source.label}
          description={container.description}
          contentHtml={container.contentField}
          terms={terms}
          activeKeys={highlightedKeys}
          selectedKeys={tab === 'mapped' ? selectedKeys : []}
          onHoverKey={(key, rect) => {
            if (key && rect) {
              setHover({ key, rect });
              setActiveKeys([key]);
            } else {
              setActiveKeys([]);
              setTimeout(() => {
                if (!hoverCardOpen.current) setHover(null);
              }, 250);
            }
          }}
          onClickKey={handleClickKey}
          onSelectText={(value) => {
            setHover(null);
            setSelection(value);
          }}
          onCounts={setCounts}
          onText={setDocumentText}
        />
      </Box>
      <ContentMappingReviewPanel
        items={items}
        counts={counts}
        relations={relations}
        tab={tab}
        onTabChange={setTab}
        selectedKeys={selectedKeys}
        onSelectedKeysChange={setSelectedKeys}
        activeKey={activeKeys[0] ?? null}
        onActiveKeyChange={(key) => setActiveKeys(key ? [key] : [])}
        sourceLabel={sourceLabel}
        analysisPending={analysisPending}
        onValidate={handleValidate}
        onIgnore={handleIgnore}
        onRestore={(keys) => run(() => actions.restore(keys))}
        onUnmap={(keys) => run(() => actions.unmap(keys))}
        onChangeType={(key, type) => run(() => actions.changeType(key, type))}
        onCreateRelation={openRelationDialog}
        onActiveRelationChange={setActiveRelation}
      />
      <MappingSelectionPopover
        selection={selection}
        onClose={() => setSelection(null)}
        onMapExisting={handleMapExisting}
        onCreate={handleCreate}
      />
      <MappingHoverCard
        item={selection ? null : hoveredItem}
        anchorRect={hover?.rect ?? null}
        occurrences={hover ? counts[hover.key] ?? 0 : 0}
        sourceLabel={sourceLabel}
        onKeepOpen={(open) => {
          hoverCardOpen.current = open;
          if (!open) setHover(null);
        }}
        onValidate={(item) => {
          setHover(null);
          handleValidate([item]);
        }}
        onIgnore={(item) => {
          setHover(null);
          handleIgnore([item]);
        }}
        onRestore={(item) => {
          setHover(null);
          run(() => actions.restore([item.key]));
        }}
        onUnmap={(item) => {
          setHover(null);
          run(() => actions.unmap([item.key]));
        }}
        onChangeType={(item, type) => run(() => actions.changeType(item.key, type))}
      />
      {/* Mounted closed, as in the knowledge graph: it loads the existing relationships when opened. */}
      <StixCoreRelationshipCreation
        open={relationDialogOpen}
        fromObjects={relationEnds.from}
        toObjects={relationEnds.to}
        confidence={container.confidence}
        defaultCreatedBy={convertCreatedBy(container)}
        defaultMarkingDefinitions={convertMarkings(container)}
        startTime={minutesBefore(1, now())}
        stopTime={now()}
        handleResult={(relation) => handleRelationCreated(relation as { id?: string })}
        onReverseRelation={() => relationDialog && setRelationDialog({ ...relationDialog, from: relationDialog.to, to: relationDialog.from })}
        onClose={() => setRelationDialogOpen(false)}
      />
    </Box>
  );
};

export type { Container as ContentMappingContainer };
export default ContentMappingReview;
