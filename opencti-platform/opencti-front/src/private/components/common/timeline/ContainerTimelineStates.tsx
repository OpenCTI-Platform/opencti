import React from 'react';
import { Link } from 'react-router';
import Skeleton from '@mui/material/Skeleton';
import { useTheme } from '@mui/material/styles';
import { Hero, HeroBody, HeroHeader, Text } from '@filigran/design-system';
import { AddOutlined, ViewTimelineOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import useTimelineColors from './useTimelineColors';

export const TIMELINE_DOCUMENTATION_URL = 'https://docs.opencti.io/latest/usage/case-timeline/';

interface ContainerTimelineEmptyStateProps {
  // The case has events, but none matches the current filters
  filtered: boolean;
  canEdit: boolean;
  regenerating: boolean;
  onAdd: () => void;
  onRegenerate: () => void;
  onClearFilters: () => void;
}

/** First use: what fills the timeline and how to start it. Filtered out: how to get the events back. */
export const ContainerTimelineEmptyState = ({ filtered, canEdit, regenerating, onAdd, onRegenerate, onClearFilters }: ContainerTimelineEmptyStateProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const colors = useTimelineColors();
  if (filtered) {
    return (
      <div
        data-testid="timeline-empty"
        role="status"
        style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: theme.spacing(1.5), padding: theme.spacing(4, 2) }}
      >
        <Text variant="content-base-medium">{t_i18n('No event matches the current filters')}</Text>
        <Button variant="secondary" size="small" onClick={onClearFilters} data-testid="timeline-empty-clear-filters">
          {t_i18n('Clear filters')}
        </Button>
      </div>
    );
  }
  return (
    <div data-testid="timeline-empty" role="status" style={{ padding: theme.spacing(2, 0) }}>
      <Hero>
        <HeroHeader
          icon={<ViewTimelineOutlined sx={{ color: colors.textSecondary }} aria-hidden={true} />}
          action={canEdit ? (
            <Button variant="primary" size="small" startIcon={<AddOutlined />} onClick={onAdd} data-testid="timeline-empty-add-event">
              {t_i18n('Add an event')}
            </Button>
          ) : undefined}
        >
          <Text variant="title-sm">{t_i18n('This timeline has no event yet')}</Text>
        </HeroHeader>
        <HeroBody>
          <Text variant="content-base">
            {t_i18n('The timeline fills itself from the knowledge of the case, the Case Autopilot steps, the hunt runs and the deployments, and from the events you add.')}
          </Text>
          <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(2), marginTop: theme.spacing(1.5) }}>
            <Link to={TIMELINE_DOCUMENTATION_URL} target="_blank" rel="noopener noreferrer">
              {t_i18n('Read the documentation')}
            </Link>
            {canEdit && (
              <Button variant="tertiary" size="small" onClick={onRegenerate} disabled={regenerating}>
                {t_i18n('Regenerate the timeline')}
              </Button>
            )}
          </div>
        </HeroBody>
      </Hero>
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
