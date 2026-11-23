import React from 'react';
import { graphql, PreloadedQuery, useFragment } from 'react-relay';
import { useNavigate } from 'react-router';
import { Card, CardTitle, Chip, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import { useFormatter } from '../../../components/i18n';
import ListCardsContent from '../../../components/list_cards/ListCardsContent';
import usePreloadedPaginationFragment from '../../../utils/hooks/usePreloadedPaginationFragment';
import type { UseLocalStorageHelpers } from '../../../utils/hooks/useLocalStorage';
import IrSparkline from './IrSparkline';
import type { IntelligenceRequirementsLinesQuery } from './__generated__/IntelligenceRequirementsLinesQuery.graphql';
import type { IntelligenceRequirements_data$key } from './__generated__/IntelligenceRequirements_data.graphql';
import type { IntelligenceRequirementsLine_node$key } from './__generated__/IntelligenceRequirementsLine_node.graphql';

// List of the requirements: shared queries (list and cards views) and the cards view.

export const PRIORITY_SEVERITY: Record<string, 'critical' | 'high' | 'medium' | 'low'> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };
// The label of a stored priority (never the raw value on screen): one map for the list, the cards, the detail and the forms
export const PRIORITY_LABEL: Record<string, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
export const IR_PRIORITIES = ['critical', 'high', 'medium', 'low'] as const;
export const priorityLabel = (t_i18n: (key: string) => string, priority: string) => t_i18n(PRIORITY_LABEL[priority] ?? priority);

export const intelligenceRequirementLineFragment = graphql`
  fragment IntelligenceRequirementsLine_node on IntelligenceRequirement {
    id
    entity_type
    name
    ir_question
    ir_priority
    ir_status
    created_at
    creators { id name }
    currentUserAccessRight
    ir_entities_count
    ir_inbox_open_count
    ir_activity(days: 7) { date value }
  }
`;

export const intelligenceRequirementsLinesFragment = graphql`
  fragment IntelligenceRequirements_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "IntelligenceRequirementOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "IntelligenceRequirementsRefetchQuery") {
    intelligenceRequirements(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_intelligenceRequirements") {
      edges {
        node {
          id
          ...IntelligenceRequirementsLine_node
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

export const intelligenceRequirementsLinesQuery = graphql`
  query IntelligenceRequirementsLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: IntelligenceRequirementOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...IntelligenceRequirements_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

// Every card has the same rows: the title and the question reserve 2 lines each, the date has its own line,
// so the figures and the sparkline sit at the same height in every card and the content fits the fixed
// card height the virtualised grid needs (rowHeight), with padding kept under the sparkline
const CARD_HEIGHT = 320;
const CARDS_TO_LOAD = 25;
const clampStyle = (lines: number): React.CSSProperties => ({
  display: '-webkit-box',
  WebkitLineClamp: lines,
  WebkitBoxOrient: 'vertical',
  overflow: 'hidden',
  minHeight: `${lines}lh`,
});

const IntelligenceRequirementCard = ({ node }: { node: IntelligenceRequirementsLine_node$key }) => {
  const { t_i18n, fsd } = useFormatter();
  const navigate = useNavigate();
  const ir = useFragment(intelligenceRequirementLineFragment, node);
  return (
    <Card onClick={() => navigate(`/dashboard/intelligence_requirements/${ir.id}`)} padding={16} gap={0} style={{ cursor: 'pointer', height: CARD_HEIGHT }}>
      <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%', minWidth: 0, gap: 1 }}>
        {/* The card is clickable through its title: the FDS Card stretches the title's control over the surface */}
        <CardTitle as="div"><span style={clampStyle(2)}>{ir.name}</span></CardTitle>
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'nowrap', minWidth: 0, overflow: 'hidden' }}>
          <Chip label={priorityLabel(t_i18n, ir.ir_priority)} severity={PRIORITY_SEVERITY[ir.ir_priority]} />
          <Chip label={t_i18n(ir.ir_status === 'active' ? 'Active' : 'Paused')} />
        </Box>
        <Text as="div" variant="content-caption" style={{ opacity: 0.7, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{fsd(ir.created_at)}</Text>
        <Text as="div" variant="content-caption" style={{ ...clampStyle(2), opacity: 0.8 }}>{ir.ir_question}</Text>
        <Box sx={{ flex: 1, minHeight: 0 }} />
        <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1 }}>
          <Box sx={{ minWidth: 0 }}>
            <Text as="div" variant="title-lg">{String(ir.ir_entities_count)}</Text>
            <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{t_i18n('Entities')}</Text>
          </Box>
          <Box sx={{ minWidth: 0 }}>
            <Text as="div" variant="title-lg">{String(ir.ir_inbox_open_count)}</Text>
            <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{t_i18n('Inbox')}</Text>
          </Box>
        </Box>
        <Box sx={{ width: '100%', height: 36, flexShrink: 0, mb: 0.5 }}>
          <IrSparkline points={ir.ir_activity} width="100%" height={36} />
        </Box>
      </Box>
    </Card>
  );
};

const IntelligenceRequirementCardDummy = () => <Card padding={16} gap={0} style={{ height: CARD_HEIGHT }}><Box /></Card>;

interface IntelligenceRequirementsCardsProps {
  queryRef: PreloadedQuery<IntelligenceRequirementsLinesQuery>;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
}

const IntelligenceRequirementsCards = ({ queryRef, setNumberOfElements }: IntelligenceRequirementsCardsProps) => {
  const { t_i18n } = useFormatter();
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<IntelligenceRequirementsLinesQuery, IntelligenceRequirements_data$key>({
    linesQuery: intelligenceRequirementsLinesQuery,
    linesFragment: intelligenceRequirementsLinesFragment,
    queryRef,
    nodePath: ['intelligenceRequirements', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  const edges = data?.intelligenceRequirements?.edges ?? [];
  if (data && edges.length === 0) {
    return <Text as="div" variant="content-base">{t_i18n('No requirement yet.')}</Text>;
  }
  // The shared infinite scroll of the cards views: the next page loads as the grid scrolls, nothing is drawn below it
  return (
    <ListCardsContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      DummyCardComponent={IntelligenceRequirementCardDummy}
      dataList={edges}
      globalCount={data?.intelligenceRequirements?.pageInfo?.globalCount ?? CARDS_TO_LOAD}
      CardComponent={IntelligenceRequirementCard}
      nbOfCardsToLoad={CARDS_TO_LOAD}
      rowHeight={CARD_HEIGHT + 30}
    />
  );
};

export default IntelligenceRequirementsCards;
