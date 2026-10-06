import React, { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { useTheme } from '@mui/material/styles';
import {
  Chip,
  Dialog,
  DialogBody,
  DialogContent,
  DialogFooter,
  DialogTitle,
  IconButton,
  Menu,
  MenuContent,
  MenuItem,
  MenuSeparator,
  MenuTrigger,
  Text,
  Textarea,
} from '@filigran/design-system';
import { CenterFocusStrongOutlined, DeleteOutlined, EditOutlined, MoreVertOutlined, PushPinOutlined, VisibilityOffOutlined, VisibilityOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import ItemConfidence from '../../../../components/ItemConfidence';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import MarkdownDisplay from '../../../../components/markdownDisplay/MarkdownDisplay';
import { useComputeLink } from '../../../../utils/hooks/useAppData';
import useTimelineColors from './useTimelineColors';
import type { TimelineListEvent } from './ContainerTimelineList';
import TimelineSourceStateChip from './TimelineSourceStateChip';
import { describeTimelineEventTimes, TIMELINE_KIND_LABELS, TIMELINE_LANE_LABELS, TIMELINE_PRECISION_LABELS, type TimelineLane, type TimelinePrecision } from './timelineUtils';

interface TimelineElementRef {
  readonly id: string;
  readonly entity_type: string;
}

export interface TimelineEventDetails extends TimelineListEvent {
  description?: string | null;
  rule_id?: string | null;
  confidence?: number | null;
  editable: boolean;
  analyst_fields: readonly string[];
  external_id?: string | null;
  createdBy?: { readonly id?: string; readonly entity_type?: string; readonly name?: string } | null;
  objectMarking?: readonly {
    readonly id: string;
    readonly definition?: string | null;
    readonly definition_type?: string | null;
    readonly x_opencti_order?: number;
    readonly x_opencti_color?: string | null;
  }[] | null;
  element?: {
    readonly id?: string;
    readonly entity_type?: string;
    readonly relationship_type?: string;
    readonly representative?: { readonly main: string } | null;
    readonly from?: TimelineElementRef | Record<string, never> | null;
    readonly to?: TimelineElementRef | Record<string, never> | null;
  } | null;
}

interface ContainerTimelineEventDrawerProps {
  event: TimelineEventDetails | null;
  canEdit: boolean;
  onClose: () => void;
  onTogglePin: (event: TimelineEventDetails) => void;
  onToggleHide: (event: TimelineEventDetails) => void;
  onSaveAnnotation: (event: TimelineEventDetails, annotation: string) => void;
  onEdit: (event: TimelineEventDetails) => void;
  onDelete: (event: TimelineEventDetails) => void;
  onCenter: (event: TimelineEventDetails) => void;
}

/** One item of the metadata grid: a secondary caption over its value. */
const MetadataItem = ({ label, children }: { label: string; children: React.ReactNode }) => {
  const colors = useTimelineColors();
  return (
    <div style={{ minWidth: 0 }}>
      <Text variant="content-caption" as="div" style={{ color: colors.textSecondary }}>{label}</Text>
      <div>{children}</div>
    </div>
  );
};

const ContainerTimelineEventDrawer = ({
  event,
  canEdit,
  onClose,
  onTogglePin,
  onToggleHide,
  onSaveAnnotation,
  onEdit,
  onDelete,
  onCenter,
}: ContainerTimelineEventDrawerProps) => {
  const { t_i18n, fldt } = useFormatter();
  const theme = useTheme();
  const colors = useTimelineColors();
  const computeLink = useComputeLink();
  const [annotation, setAnnotation] = useState(event?.annotation ?? '');
  const [annotating, setAnnotating] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  useEffect(() => {
    setAnnotation(event?.annotation ?? '');
    setAnnotating(false);
  }, [event?.id, event?.annotation]);

  if (!event) {
    return <Drawer title={t_i18n('Timeline event')} open={false} onClose={onClose} />;
  }
  const lane = event.lane as TimelineLane;
  // Pin, hide and annotate follow the rights of the user on this event (container and confidence of the event)
  const canContribute = canEdit && event.annotatable !== false;
  const element = event.element && event.element.id ? event.element : null;
  const elementLink = element ? computeLink({
    id: element.id,
    entity_type: element.entity_type,
    relationship_type: element.relationship_type,
    from: element.from && 'id' in element.from ? element.from as TimelineElementRef : null,
    to: element.to && 'id' in element.to ? element.to as TimelineElementRef : null,
  }) : undefined;
  const author = event.createdBy?.name ? event.createdBy : null;
  const authorLink = author?.id && author.entity_type ? computeLink({ id: author.id, entity_type: author.entity_type }) : undefined;
  const hasConfidence = event.confidence !== null && event.confidence !== undefined;
  const markings = event.objectMarking ?? [];
  const annotationChanged = annotation !== (event.annotation ?? '');

  const headerActions = (
    <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
      {canEdit && event.editable && (
        <Button variant="secondary" size="small" startIcon={<EditOutlined fontSize="small" />} onClick={() => onEdit(event)} data-testid="timeline-event-edit">
          {t_i18n('Edit')}
        </Button>
      )}
      {canContribute && (
        <Button variant="secondary" size="small" startIcon={<PushPinOutlined fontSize="small" />} onClick={() => onTogglePin(event)} data-testid="timeline-event-pin">
          {event.pinned ? t_i18n('Unpin') : t_i18n('Pin')}
        </Button>
      )}
      <Menu>
        <MenuTrigger asChild>
          <IconButton priority="tertiary" size="sm" aria-label={t_i18n('More actions')} icon={<MoreVertOutlined fontSize="small" />} data-testid="timeline-event-more" />
        </MenuTrigger>
        <MenuContent align="end">
          <MenuItem onSelect={() => onCenter(event)}>
            <CenterFocusStrongOutlined fontSize="small" />
            {t_i18n('Center on the timeline')}
          </MenuItem>
          {canContribute && (
            <MenuItem onSelect={() => onToggleHide(event)} data-testid="timeline-event-hide">
              {event.hidden ? <VisibilityOutlined fontSize="small" /> : <VisibilityOffOutlined fontSize="small" />}
              {event.hidden ? t_i18n('Show') : t_i18n('Hide')}
            </MenuItem>
          )}
          {canEdit && event.editable && (
            <>
              <MenuSeparator />
              <MenuItem onSelect={() => setConfirmDelete(true)} data-testid="timeline-event-delete">
                <DeleteOutlined fontSize="small" />
                {t_i18n('Delete')}
              </MenuItem>
            </>
          )}
        </MenuContent>
      </Menu>
    </div>
  );

  return (
    <Drawer title={event.title} open={true} onClose={onClose} size="medium" header={headerActions}>
      <>
        <div data-testid="timeline-event-drawer" style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2.5) }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
            <Text variant="content-base" style={{ color: colors.textSecondary }}>{t_i18n(TIMELINE_KIND_LABELS[event.kind] ?? 'Timeline event')}</Text>
            <TimelineSourceStateChip state={event.source_state} />
            {event.pinned && <Chip label={t_i18n('Pinned')} severity="info" size="sm" />}
            {event.hidden && <Chip label={t_i18n('Hidden')} size="sm" />}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: theme.spacing(2, 3) }} data-testid="timeline-event-metadata">
            <MetadataItem label={t_i18n('Time')}>
              <Text variant="content-base" as="div">
                {describeTimelineEventTimes(event, t_i18n, fldt)}
              </Text>
              <Text variant="content-caption" as="div" style={{ color: colors.textSecondary }}>
                {t_i18n(TIMELINE_PRECISION_LABELS[event.precision as TimelinePrecision] ?? 'Exact')}
              </Text>
            </MetadataItem>
            <MetadataItem label={t_i18n('Lane')}>
              <Chip label={t_i18n(TIMELINE_LANE_LABELS[lane] ?? 'Custom')} color={colors.lanes[lane]} size="sm" />
            </MetadataItem>
            <MetadataItem label={t_i18n('Source')}>
              <Text variant="content-base" as="div">
                {event.source === 'manual' ? t_i18n('Analyst milestone') : t_i18n('Derived from the knowledge')}
              </Text>
            </MetadataItem>
            {author && (
              <MetadataItem label={t_i18n('Author')}>
                <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
                  <ItemIcon type={author.entity_type ?? 'Identity'} size="small" />
                  {authorLink ? <Link to={authorLink}>{author.name}</Link> : <Text variant="content-base">{author.name}</Text>}
                </div>
              </MetadataItem>
            )}
            {hasConfidence && (
              <MetadataItem label={t_i18n('Confidence')}>
                <ItemConfidence confidence={event.confidence} entityType="Timeline-Event" />
              </MetadataItem>
            )}
            {element && (
              <MetadataItem label={t_i18n('Element')}>
                <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), minWidth: 0 }}>
                  <ItemIcon type={element.entity_type} size="small" />
                  <div style={{ minWidth: 0 }}>
                    {elementLink ? (
                      <Link to={elementLink} data-testid="timeline-event-element">{element.representative?.main ?? t_i18n(`entity_${element.entity_type}`)}</Link>
                    ) : (
                      <Text variant="content-base">{element.representative?.main ?? t_i18n(`entity_${element.entity_type}`)}</Text>
                    )}
                    <Text variant="content-caption" as="div" style={{ color: colors.textSecondary }}>
                      {element.relationship_type ? t_i18n(`relationship_${element.relationship_type}`) : t_i18n(`entity_${element.entity_type}`)}
                    </Text>
                  </div>
                </div>
              </MetadataItem>
            )}
            {markings.length > 0 && (
              <MetadataItem label={t_i18n('Marking')}>
                <ItemMarkings markingDefinitions={markings} limit={4} />
              </MetadataItem>
            )}
          </div>
          {event.description && (
            <div>
              <Text variant="content-caption" as="div" style={{ color: colors.textSecondary }}>{t_i18n('Description')}</Text>
              <MarkdownDisplay content={event.description} limit={2000} />
            </div>
          )}
          {(event.annotation || annotating) && (
            <div>
              <Text variant="content-caption" as="div" style={{ color: colors.textSecondary }}>{t_i18n('Annotation')}</Text>
              {canContribute && annotating ? (
                <>
                  <Textarea
                    value={annotation}
                    onChange={(changeEvent) => setAnnotation(changeEvent.target.value)}
                    aria-label={t_i18n('Annotation')}
                    placeholder={t_i18n('Add the analyst context of this event')}
                    rows={3}
                    maxLength={10000}
                    autoFocus={true}
                    data-testid="timeline-annotation-input"
                  />
                  <div style={{ marginTop: theme.spacing(1), display: 'flex', justifyContent: 'flex-end', gap: theme.spacing(1) }}>
                    <Button
                      variant="tertiary"
                      size="small"
                      onClick={() => {
                        setAnnotation(event.annotation ?? '');
                        setAnnotating(false);
                      }}
                    >
                      {t_i18n('Cancel')}
                    </Button>
                    <Button
                      size="small"
                      disabled={!annotationChanged}
                      onClick={() => {
                        onSaveAnnotation(event, annotation);
                        setAnnotating(false);
                      }}
                    >
                      {t_i18n('Save the annotation')}
                    </Button>
                  </div>
                </>
              ) : (
                <Text variant="content-base" as="div" style={{ whiteSpace: 'pre-wrap' }}>{event.annotation}</Text>
              )}
            </div>
          )}
          {canContribute && !annotating && (
            <div>
              <Button variant="tertiary" size="small" startIcon={<EditOutlined fontSize="small" />} onClick={() => setAnnotating(true)} data-testid="timeline-event-annotate">
                {event.annotation ? t_i18n('Edit the annotation') : t_i18n('Add an annotation')}
              </Button>
            </div>
          )}
          {!event.editable && canContribute && (
            <Text variant="content-caption" as="p" style={{ color: colors.textSecondary }}>
              {t_i18n('Derived events follow the knowledge of the case: they can be pinned, hidden and annotated, not edited.')}
            </Text>
          )}
        </div>
        <Dialog open={confirmDelete} onOpenChange={setConfirmDelete}>
          <DialogContent>
            <DialogTitle>{t_i18n('Delete the event {title}?', { values: { title: event.title } })}</DialogTitle>
            <DialogBody>{t_i18n('The event is removed from the timeline and its anchors are recomputed.')}</DialogBody>
            <DialogFooter>
              <Button variant="secondary" onClick={() => setConfirmDelete(false)}>{t_i18n('Cancel')}</Button>
              <Button
                intent="destructive"
                onClick={() => {
                  setConfirmDelete(false);
                  onDelete(event);
                }}
                data-testid="timeline-event-delete-confirm"
              >
                {t_i18n('Delete')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </>
    </Drawer>
  );
};

export default ContainerTimelineEventDrawer;
