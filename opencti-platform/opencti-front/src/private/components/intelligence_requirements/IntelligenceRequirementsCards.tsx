import React from 'react';
import { graphql, PreloadedQuery, useFragment } from 'react-relay';
import { useNavigate } from 'react-router';
import { Card, CardTitle, Chip, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import usePreloadedPaginationFragment from '../../../utils/hooks/usePreloadedPaginationFragment';
import type { UseLocalStorageHelpers } from '../../../utils/hooks/useLocalStorage';
import IrSparkline from './IrSparkline';
import type { IntelligenceRequirementsLinesQuery } from './__generated__/IntelligenceRequirementsLinesQuery.graphql';
import type { IntelligenceRequirements_data$key } from './__generated__/IntelligenceRequirements_data.graphql';
import type { IntelligenceRequirementsLine_node$key } from './__generated__/IntelligenceRequirementsLine_node.graphql';

// List of the requirements: shared queries (list and cards views) and the cards view.

export const PRIORITY_SEVERITY: Record<string, 'critical' | 'high' | 'medium' | 'low'> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };

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

const CARD_HEIGHT = 250;
const clampStyle = (lines: number): React.CSSProperties => ({ display: '-webkit-box', WebkitLineClamp: lines, WebkitBoxOrient: 'vertical', overflow: 'hidden' });

const IntelligenceRequirementCard = ({ node }: { node: IntelligenceRequirementsLine_node$key }) => {
  const { t_i18n, fsd } = useFormatter();
  const navigate = useNavigate();
  const ir = useFragment(intelligenceRequirementLineFragment, node);
  return (
    <Card onClick={() => navigate(`/dashboard/intelligence_requirements/${ir.id}`)} padding={16} gap={0} style={{ cursor: 'pointer', height: CARD_HEIGHT }}>
      <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%', minWidth: 0, gap: 1 }}>
        {/* The card is clickable through its title: the FDS Card stretches the title's control over the surface */}
        <CardTitle as="div"><span style={clampStyle(2)}>{ir.name}</span></CardTitle>
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
          <Chip label={t_i18n(ir.ir_priority)} severity={PRIORITY_SEVERITY[ir.ir_priority]} />
          <Chip label={t_i18n(ir.ir_status === 'active' ? 'Active' : 'Paused')} />
          <Text as="span" variant="content-caption" style={{ opacity: 0.7 }}>{fsd(ir.created_at)}</Text>
        </Box>
        <Text as="div" variant="content-caption" style={{ ...clampStyle(2), opacity: 0.8 }}>{ir.ir_question}</Text>
        <Box sx={{ flex: 1 }} />
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
        <Box sx={{ width: '100%', height: 36 }}>
          <IrSparkline points={ir.ir_activity} width="100%" height={36} />
        </Box>
      </Box>
    </Card>
  );
};

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
  const nodes = (data?.intelligenceRequirements?.edges ?? []).map((e) => e.node);
  if (nodes.length === 0) {
    return <Text as="div" variant="content-base">{t_i18n('No requirement yet.')}</Text>;
  }
  return (
    <>
      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 2 }}>
        {nodes.map((node) => <IntelligenceRequirementCard key={node.id} node={node} />)}
      </Box>
      {hasMore() && (
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
          <Button variant="secondary" onClick={() => loadMore(25)} disabled={isLoadingMore()}>{t_i18n('Load more')}</Button>
        </Box>
      )}
    </>
  );
};

export default IntelligenceRequirementsCards;
