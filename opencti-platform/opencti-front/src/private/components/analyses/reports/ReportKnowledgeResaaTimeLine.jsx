import React, { useEffect, useMemo, useState } from 'react';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Divider from '@mui/material/Divider';
import Typography from '@mui/material/Typography';
import {
  DescriptionOutlined,
  PersonOutline,
  VisibilityOutlined,
} from '@mui/icons-material';
import { Link } from 'react-router-dom';
import { getSecondaryRepresentative, getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import ItemIcon from '../../../../components/ItemIcon';
import { resolveLink } from '../../../../utils/Entity';
import { useFormatter } from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import ReportKnowledgeTimeLine, { reportKnowledgeTimeLineQuery } from './ReportKnowledgeTimeLine';
import ResaaTimelineTimeRangeFilter, {
  alignTimelineIntervalToGranularity,
  computeResaaTimelineInterval,
  computeTimelineAxisInterval,
  generateCalendarTickValues,
  inferDefaultTimeGranularity,
  snapIntervalToTickValues,
} from './ResaaTimelineTimeRangeFilter';

export { reportKnowledgeTimeLineQuery as reportKnowledgeResaaTimeLineQuery };

const parseEventDate = (node, dateAttribute) => {
  const value = node[dateAttribute];
  if (!value) {
    return null;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
};

const RANGE_EDGE_TOLERANCE_MS = 60 * 1000;

const toTimestamp = (date) => {
  if (date instanceof Date) {
    return date.getTime();
  }
  const parsed = new Date(date);
  return Number.isNaN(parsed.getTime()) ? null : parsed.getTime();
};

const isWithinTimeRange = (timestamp, rangeStart, rangeEnd) => (
  timestamp >= rangeStart - RANGE_EDGE_TOLERANCE_MS
  && timestamp <= rangeEnd + RANGE_EDGE_TOLERANCE_MS
);

const isFullTimelineRange = (activeRange, fullRange) => (
  Math.abs(activeRange[0].getTime() - fullRange[0].getTime()) <= RANGE_EDGE_TOLERANCE_MS
  && Math.abs(activeRange[1].getTime() - fullRange[1].getTime()) <= RANGE_EDGE_TOLERANCE_MS
);

const TIMELINE_RAIL_COLOR = '#e5e7eb';
const CARD_BORDER_COLOR = '#e8eaed';

export const ReportKnowledgeResaaTimeLineView = ({
  report,
  dateAttribute,
  displayRelationships,
}) => {
  const { mhd, rd, t_i18n } = useFormatter();
  const { edges } = report.objects;
  const [selectedTimeRange, setSelectedTimeRange] = useState(null);
  const [timeGranularity, setTimeGranularity] = useState('daily');

  const timelineMarkers = useMemo(
    () => edges.flatMap((edge) => {
      const { node } = edge;
      const time = parseEventDate(node, dateAttribute);
      if (!time) {
        return [];
      }
      const entityType = displayRelationships
        ? node.from?.entity_type ?? node.entity_type
        : node.entity_type;
      return [{
        id: node.id,
        time,
        color: itemColor(entityType),
      }];
    }),
    [edges, dateAttribute, displayRelationships],
  );

  const dataTimeExtent = useMemo(
    () => computeResaaTimelineInterval(timelineMarkers.map((marker) => marker.time)),
    [timelineMarkers],
  );

  const timelineAxisInterval = useMemo(
    () => computeTimelineAxisInterval(
      timeGranularity,
      timelineMarkers.map((marker) => marker.time),
    ),
    [timeGranularity, timelineMarkers],
  );

  const activeTimeRange = selectedTimeRange ?? timelineAxisInterval;
  const effectiveTimeRange = useMemo(() => {
    const aligned = alignTimelineIntervalToGranularity(timelineAxisInterval, timeGranularity);
    const ticks = generateCalendarTickValues(aligned, timeGranularity);
    return snapIntervalToTickValues(activeTimeRange, ticks, aligned);
  }, [activeTimeRange, timeGranularity, timelineAxisInterval]);
  const rangeStart = effectiveTimeRange[0].getTime();
  const rangeEnd = effectiveTimeRange[1].getTime();
  const showFullRange = isFullTimelineRange(effectiveTimeRange, timelineAxisInterval);

  useEffect(() => {
    setSelectedTimeRange(null);
    setTimeGranularity(inferDefaultTimeGranularity(dataTimeExtent));
  }, [dataTimeExtent[0].getTime(), dataTimeExtent[1].getTime()]);

  const handleTimeRangeChange = (interval) => {
    if (!interval || interval.length !== 2) {
      return;
    }
    const start = toTimestamp(interval[0]);
    const end = toTimestamp(interval[1]);
    if (start === null || end === null) {
      return;
    }
    const aligned = alignTimelineIntervalToGranularity(timelineAxisInterval, timeGranularity);
    const ticks = generateCalendarTickValues(aligned, timeGranularity);
    setSelectedTimeRange(
      snapIntervalToTickValues([new Date(start), new Date(end)], ticks, aligned),
    );
  };

  const handleGranularityChange = (granularity) => {
    setTimeGranularity(granularity);
    setSelectedTimeRange(null);
  };

  const filteredEdges = useMemo(
    () => edges.filter((edge) => {
      const time = parseEventDate(edge.node, dateAttribute);
      if (!time) {
        return showFullRange;
      }
      return isWithinTimeRange(time.getTime(), rangeStart, rangeEnd);
    }),
    [edges, dateAttribute, rangeStart, rangeEnd, showFullRange],
  );

  const resolveNodeLink = (node) => {
    const entityType = displayRelationships ? node.from?.entity_type : node.entity_type;
    const entityId = displayRelationships ? node.from?.id : node.id;
    if (!entityType || !entityId) {
      return null;
    }
    const baseLink = resolveLink(entityType);
    if (displayRelationships) {
      return `${baseLink}/${entityId}/knowledge/relations/${node.id}`;
    }
    return `${baseLink}/${entityId}`;
  };

  const resolveEventDate = (node) => node[dateAttribute];

  const resolveCreatorName = (node) => {
    if (displayRelationships) {
      return node.createdBy?.name ?? node.from?.createdBy?.name;
    }
    return node.createdBy?.name;
  };

  const resolveMarkingCount = (node) => {
    const markings = displayRelationships
      ? (node.objectMarking ?? node.from?.objectMarking)
      : node.objectMarking;
    return markings?.length ?? 0;
  };

  return (
    <Box
      id="container"
      sx={{
        width: '100%',
        height: '100%',
        overflow: 'auto',
        paddingBottom: 10,
        paddingX: { xs: 2, sm: 4 },
        paddingTop: 3,
        backgroundColor: (theme) => theme.palette.background.default,
      }}
    >
      <Box sx={{ maxWidth: 960, margin: '0 auto' }}>
        <ResaaTimelineTimeRangeFilter
          items={timelineMarkers}
          timelineInterval={timelineAxisInterval}
          selectedInterval={activeTimeRange}
          granularity={timeGranularity}
          onGranularityChange={handleGranularityChange}
          onChange={handleTimeRangeChange}
        />
        {filteredEdges.length === 0 && (
          <Typography
            variant="body2"
            color="text.secondary"
            sx={{ textAlign: 'center', py: 4 }}
          >
            {t_i18n('No results found')}
          </Typography>
        )}
        {filteredEdges.map((edge, index) => {
          const { node } = edge;
          const link = resolveNodeLink(node);
          const eventDate = resolveEventDate(node);
          const title = getMainRepresentative(node);
          const description = getSecondaryRepresentative(node);
          const creatorName = resolveCreatorName(node);
          const markingCount = resolveMarkingCount(node);
          const isLast = index === filteredEdges.length - 1;
          const entityColor = itemColor(
            displayRelationships ? node.from?.entity_type ?? node.entity_type : node.entity_type,
          );

          return (
            <Box
              key={node.id}
              sx={{
                display: 'flex',
                gap: 2.5,
                alignItems: 'stretch',
              }}
            >
              <Box
                sx={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  width: 44,
                  flexShrink: 0,
                }}
              >
                {link ? (
                  <Box
                    component={Link}
                    to={link}
                    sx={{
                      width: 44,
                      height: 44,
                      borderRadius: '50%',
                      border: `2px solid ${entityColor}`,
                      backgroundColor: 'background.paper',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      boxShadow: '0 1px 4px rgba(0, 0, 0, 0.08)',
                      textDecoration: 'none',
                      zIndex: 1,
                      '&:hover': {
                        boxShadow: '0 2px 8px rgba(0, 0, 0, 0.12)',
                      },
                    }}
                  >
                    <ItemIcon
                      type={displayRelationships ? node.from?.entity_type : node.entity_type}
                      size="small"
                    />
                  </Box>
                ) : (
                  <Box
                    sx={{
                      width: 44,
                      height: 44,
                      borderRadius: '50%',
                      border: `2px solid ${entityColor}`,
                      backgroundColor: 'background.paper',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      boxShadow: '0 1px 4px rgba(0, 0, 0, 0.08)',
                    }}
                  >
                    <ItemIcon
                      type={displayRelationships ? node.from?.entity_type : node.entity_type}
                      size="small"
                    />
                  </Box>
                )}
                {!isLast && (
                  <Box
                    sx={{
                      width: 2,
                      flexGrow: 1,
                      minHeight: 28,
                      backgroundColor: TIMELINE_RAIL_COLOR,
                      marginY: 0.5,
                    }}
                  />
                )}
              </Box>

              <Box
                sx={{
                  flex: 1,
                  marginBottom: isLast ? 0 : 3,
                  border: `1px solid ${CARD_BORDER_COLOR}`,
                  borderRadius: 2,
                  backgroundColor: 'background.paper',
                  padding: 2.5,
                }}
              >
                <Box
                  sx={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'flex-start',
                    gap: 2,
                  }}
                >
                  <Box sx={{ flex: 1, minWidth: 0 }}>
                    <Typography
                      variant="h6"
                      sx={{
                        fontWeight: 600,
                        fontSize: '1rem',
                        lineHeight: 1.4,
                        color: 'text.primary',
                      }}
                    >
                      {title}
                    </Typography>
                    {displayRelationships && (
                      <Typography
                        variant="caption"
                        sx={{ color: 'text.secondary', display: 'block', marginTop: 0.25 }}
                      >
                        {t_i18n(`relationship_${node.entity_type}`)}
                      </Typography>
                    )}
                  </Box>
                  <Box sx={{ textAlign: 'right', flexShrink: 0 }}>
                    <Typography
                      variant="body2"
                      sx={{ fontWeight: 600, color: 'text.primary', lineHeight: 1.3 }}
                    >
                      {rd(eventDate)}
                    </Typography>
                    <Typography
                      variant="caption"
                      sx={{ color: 'text.secondary', display: 'block', marginTop: 0.25 }}
                    >
                      {mhd(eventDate)}
                    </Typography>
                  </Box>
                </Box>

                {description && (
                  <Box sx={{ marginTop: 1.5, color: 'text.secondary', fontSize: '0.875rem' }}>
                    <MarkdownDisplay content={description} limit={200} />
                  </Box>
                )}

                <Divider sx={{ marginY: 2 }} />

                <Box
                  sx={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    gap: 2,
                    flexWrap: 'wrap',
                  }}
                >
                  <Box
                    sx={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 2.5,
                      flexWrap: 'wrap',
                    }}
                  >
                    {creatorName && (
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                        <PersonOutline sx={{ fontSize: 18, color: 'text.secondary' }} />
                        <Typography variant="body2" color="text.secondary">
                          {creatorName}
                        </Typography>
                      </Box>
                    )}
                    {markingCount > 0 && (
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                        <DescriptionOutlined sx={{ fontSize: 18, color: 'text.secondary' }} />
                        <Typography variant="body2" color="text.secondary">
                          {markingCount}
                        </Typography>
                      </Box>
                    )}
                  </Box>
                  {link && (
                    <Button
                      component={Link}
                      to={link}
                      variant="outlined"
                      size="small"
                      startIcon={<VisibilityOutlined fontSize="small" />}
                      sx={{
                        textTransform: 'none',
                        borderRadius: 1.5,
                        borderColor: CARD_BORDER_COLOR,
                        color: 'text.primary',
                        fontWeight: 500,
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {t_i18n('View Details')}
                    </Button>
                  )}
                </Box>
              </Box>
            </Box>
          );
        })}
      </Box>
    </Box>
  );
};

const ReportKnowledgeResaaTimeLine = (props) => (
  <ReportKnowledgeTimeLine
    report={props.report}
    dateAttribute={props.dateAttribute}
    displayRelationships={props.displayRelationships}
    renderTimeline={ReportKnowledgeResaaTimeLineView}
  />
);

export default ReportKnowledgeResaaTimeLine;
