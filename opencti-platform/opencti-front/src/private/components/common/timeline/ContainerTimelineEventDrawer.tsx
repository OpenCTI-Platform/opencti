import React, { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { Chip, Dialog, DialogBody, DialogContent, DialogFooter, DialogTitle, Textarea } from '@filigran/design-system';
import { CenterFocusStrongOutlined, DeleteOutlined, EditOutlined, PushPinOutlined, VisibilityOffOutlined, VisibilityOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import MarkdownDisplay from '../../../../components/markdownDisplay/MarkdownDisplay';
import { useComputeLink } from '../../../../utils/hooks/useAppData';
import useTimelineColors from './useTimelineColors';
import type { TimelineListEvent } from './ContainerTimelineList';
import { TIMELINE_KIND_LABELS, TIMELINE_LANE_LABELS, TIMELINE_PRECISION_LABELS, type TimelineLane, type TimelinePrecision } from './timelineUtils';

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
  createdBy?: { readonly name?: string } | null;
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

const Section = ({ title, children }: { title: string; children: React.ReactNode }) => {
  const colors = useTimelineColors();
  return (
    <div style={{ marginTop: 20 }}>
      <div style={{ fontSize: 12, fontWeight: 600, color: colors.textSecondary, textTransform: 'uppercase', marginBottom: 6 }}>{title}</div>
      {children}
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
  const colors = useTimelineColors();
  const computeLink = useComputeLink();
  const [annotation, setAnnotation] = useState(event?.annotation ?? '');
  const [confirmDelete, setConfirmDelete] = useState(false);

  useEffect(() => {
    setAnnotation(event?.annotation ?? '');
  }, [event?.id, event?.annotation]);

  if (!event) {
    return <Drawer title={t_i18n('Timeline event')} open={false} onClose={onClose} />;
  }
  const lane = event.lane as TimelineLane;
  const element = event.element && event.element.id ? event.element : null;
  const elementLink = element ? computeLink({
    id: element.id,
    entity_type: element.entity_type,
    relationship_type: element.relationship_type,
    from: element.from && 'id' in element.from ? element.from as TimelineElementRef : null,
    to: element.to && 'id' in element.to ? element.to as TimelineElementRef : null,
  }) : undefined;
  const annotationChanged = annotation !== (event.annotation ?? '');

  return (
    <Drawer title={event.title} open={true} onClose={onClose}>
      <>
        <div data-testid="timeline-event-drawer">
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            <Chip label={t_i18n(TIMELINE_LANE_LABELS[lane] ?? lane)} color={colors.lanes[lane]} />
            <Chip label={t_i18n(TIMELINE_KIND_LABELS[event.kind] ?? event.kind)} />
            <Chip
              label={t_i18n(TIMELINE_PRECISION_LABELS[event.precision as TimelinePrecision] ?? event.precision)}
              severity={event.precision === 'exact' ? 'low' : 'medium'}
            />
            <Chip label={event.source === 'manual' ? t_i18n('Analyst milestone') : t_i18n('Derived from the knowledge')} severity="info" />
            {event.pinned && <Chip label={t_i18n('Pinned')} severity="high" />}
            {event.hidden && <Chip label={t_i18n('Hidden')} />}
          </div>
          <Section title={t_i18n('When')}>
            <div>{fldt(event.event_time)}</div>
            {event.event_end_time && <div>{`\u2192 ${fldt(event.event_end_time)}`}</div>}
          </Section>
          {element && (
            <Section title={t_i18n('Element')}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <ItemIcon type={element.entity_type} />
                {elementLink ? (
                  <Link to={elementLink} data-testid="timeline-event-element">{element.representative?.main ?? element.entity_type}</Link>
                ) : (
                  <span>{element.representative?.main ?? element.entity_type}</span>
                )}
              </div>
            </Section>
          )}
          {event.description && (
            <Section title={t_i18n('Description')}>
              <MarkdownDisplay content={event.description} limit={2000} />
            </Section>
          )}
          {(event.objectMarking ?? []).length > 0 && (
            <Section title={t_i18n('Marking')}>
              <ItemMarkings markingDefinitions={event.objectMarking ?? []} limit={4} />
            </Section>
          )}
          {(event.createdBy?.name || (event.confidence !== null && event.confidence !== undefined)) && (
            <Section title={t_i18n('Source')}>
              {event.createdBy?.name && <div>{`${t_i18n('Author')}: ${event.createdBy.name}`}</div>}
              {event.confidence !== null && event.confidence !== undefined && <div>{`${t_i18n('Confidence')}: ${event.confidence}`}</div>}
            </Section>
          )}
          <Section title={t_i18n('Annotation')}>
            {canEdit ? (
              <>
                <Textarea
                  value={annotation}
                  onChange={(changeEvent) => setAnnotation(changeEvent.target.value)}
                  aria-label={t_i18n('Annotation')}
                  placeholder={t_i18n('Add the analyst context of this event')}
                  rows={3}
                  maxLength={10000}
                  data-testid="timeline-annotation-input"
                />
                <div style={{ marginTop: 8, display: 'flex', justifyContent: 'flex-end' }}>
                  <Button size="small" disabled={!annotationChanged} onClick={() => onSaveAnnotation(event, annotation)}>
                    {t_i18n('Save the annotation')}
                  </Button>
                </div>
              </>
            ) : (
              <div style={{ fontStyle: 'italic' }}>{event.annotation || t_i18n('No annotation')}</div>
            )}
          </Section>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 24 }}>
            <Button variant="secondary" size="small" startIcon={<CenterFocusStrongOutlined />} onClick={() => onCenter(event)}>
              {t_i18n('Center on the timeline')}
            </Button>
            {canEdit && (
              <>
                <Button variant="secondary" size="small" startIcon={<PushPinOutlined />} onClick={() => onTogglePin(event)} data-testid="timeline-event-pin">
                  {event.pinned ? t_i18n('Unpin') : t_i18n('Pin')}
                </Button>
                <Button
                  variant="secondary"
                  size="small"
                  startIcon={event.hidden ? <VisibilityOutlined /> : <VisibilityOffOutlined />}
                  onClick={() => onToggleHide(event)}
                  data-testid="timeline-event-hide"
                >
                  {event.hidden ? t_i18n('Show') : t_i18n('Hide')}
                </Button>
                {event.editable && (
                  <>
                    <Button variant="secondary" size="small" startIcon={<EditOutlined />} onClick={() => onEdit(event)} data-testid="timeline-event-edit">
                      {t_i18n('Edit')}
                    </Button>
                    <Button variant="secondary" intent="destructive" size="small" startIcon={<DeleteOutlined />} onClick={() => setConfirmDelete(true)} data-testid="timeline-event-delete">
                      {t_i18n('Delete')}
                    </Button>
                  </>
                )}
              </>
            )}
          </div>
          {!event.editable && canEdit && (
            <p style={{ marginTop: 12, fontSize: 12, color: colors.textSecondary }}>
              {t_i18n('Derived events follow the knowledge of the case: they can be pinned, hidden and annotated, not edited.')}
            </p>
          )}
        </div>
        <Dialog open={confirmDelete} onOpenChange={setConfirmDelete}>
          <DialogContent>
            <DialogTitle>{t_i18n('Delete this milestone?')}</DialogTitle>
            <DialogBody>{t_i18n('The milestone is removed from the timeline and its anchors are recomputed.')}</DialogBody>
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
