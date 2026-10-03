import React from 'react';
import Skeleton from '@mui/material/Skeleton';
import { useTheme } from '@mui/material/styles';
import { FilterAltOffOutlined, ViewTimelineOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import useTimelineColors from './useTimelineColors';

interface ContainerTimelineEmptyStateProps {
  // The case has events, but none matches the current filters
  filtered: boolean;
  canEdit: boolean;
  regenerating: boolean;
  onAdd: () => void;
  onRegenerate: () => void;
  onClearFilters: () => void;
}

/** Why the timeline shows nothing, and what to do next. */
export const ContainerTimelineEmptyState = ({ filtered, canEdit, regenerating, onAdd, onRegenerate, onClearFilters }: ContainerTimelineEmptyStateProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const colors = useTimelineColors();
  const Icon = filtered ? FilterAltOffOutlined : ViewTimelineOutlined;
  return (
    <div
      data-testid="timeline-empty"
      role="status"
      style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: theme.spacing(1.5), padding: theme.spacing(5, 2), textAlign: 'center' }}
    >
      <Icon sx={{ fontSize: 40, color: colors.textSecondary }} aria-hidden={true} />
      <div style={{ fontSize: 15, fontWeight: 600 }}>
        {filtered ? t_i18n('No event matches the current filters') : t_i18n('This timeline has no event yet')}
      </div>
      <div style={{ maxWidth: 520, fontSize: 13, color: colors.textSecondary }}>
        {filtered
          ? t_i18n('Clear the filters or widen the search to see the other events of the case.')
          : t_i18n('Events appear as knowledge, tasks, notes and files are added to the case. Record what the knowledge cannot tell with a milestone.')}
      </div>
      <div style={{ display: 'flex', gap: theme.spacing(1), marginTop: theme.spacing(0.5) }}>
        {filtered && (
          <Button variant="secondary" size="small" onClick={onClearFilters} data-testid="timeline-empty-clear-filters">
            {t_i18n('Clear filters')}
          </Button>
        )}
        {!filtered && canEdit && (
          <>
            <Button variant="primary" size="small" onClick={onAdd} data-testid="timeline-empty-add-milestone">
              {t_i18n('Add milestone')}
            </Button>
            <Button variant="secondary" size="small" onClick={onRegenerate} disabled={regenerating}>
              {t_i18n('Regenerate the timeline')}
            </Button>
          </>
        )}
      </div>
    </div>
  );
};

const SKELETON_ROWS = 6;

/** Placeholder of the events while they load, shaped like the timeline rows. */
export const ContainerTimelineSkeleton = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  return (
    <div role="progressbar" aria-label={t_i18n('Loading the timeline')} style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1), padding: theme.spacing(2, 0) }}>
      {Array.from({ length: SKELETON_ROWS }, (_, index) => (
        <div key={index} style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(2) }}>
          <Skeleton variant="text" width={110} />
          <Skeleton variant="rounded" height={22} width={`${35 + ((index * 17) % 45)}%`} />
        </div>
      ))}
    </div>
  );
};
