import React, { Component, type ReactNode } from 'react';
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
  // The case has events, but the timeline settings (enabled lanes, hidden kinds) hide every one of them
  hiddenBySettings?: boolean;
  canEdit: boolean;
  regenerating: boolean;
  onAdd: () => void;
  onRegenerate: () => void;
  onClearFilters: () => void;
  onOpenSettings?: () => void;
}

/** First use: what fills the timeline and how to start it. Filtered out or hidden by the settings: how to get the events back. */
export const ContainerTimelineEmptyState = ({
  filtered,
  hiddenBySettings = false,
  canEdit,
  regenerating,
  onAdd,
  onRegenerate,
  onClearFilters,
  onOpenSettings,
}: ContainerTimelineEmptyStateProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const colors = useTimelineColors();
  if (hiddenBySettings) {
    return (
      <div
        data-testid="timeline-empty"
        role="status"
        style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: theme.spacing(1.5), padding: theme.spacing(4, 2) }}
      >
        <Text variant="content-base-medium">{t_i18n('Every event of the case is in a lane or a kind the timeline settings hide.')}</Text>
        {canEdit && onOpenSettings && (
          <Button variant="secondary" size="small" onClick={onOpenSettings} data-testid="timeline-empty-open-settings">
            {t_i18n('Timeline settings')}
          </Button>
        )}
      </div>
    );
  }
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

interface ContainerTimelineErrorStateProps {
  onRetry: () => void;
}

/** The events could not be loaded: say so and offer to load them again. */
export const ContainerTimelineErrorState = ({ onRetry }: ContainerTimelineErrorStateProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  return (
    <div
      data-testid="timeline-error"
      role="alert"
      style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: theme.spacing(1.5), padding: theme.spacing(4, 2) }}
    >
      <Text variant="content-base-medium">{t_i18n('The timeline could not be loaded')}</Text>
      <Text variant="content-caption">{t_i18n('Check your connection, then try again. If the problem persists, contact your administrator.')}</Text>
      <Button variant="secondary" size="small" onClick={onRetry} data-testid="timeline-error-retry">
        {t_i18n('Retry')}
      </Button>
    </div>
  );
};

type ErrorResponse = { status?: number; errors?: readonly { extensions?: { code?: string } }[] };
type RequestError = { res?: ErrorResponse; data?: { res?: ErrorResponse } };
const TRANSIENT_ERROR_CODES = ['DATABASE_ERROR', 'LOCK_ERROR', 'UNKNOWN_ERROR'];

// Only a transient failure of the server is worth a retry. Any other error (session, access, not found, code)
// goes on to the authentication and page error boundaries, which handle each of them.
const isRetryableError = (error: unknown) => {
  const response = (error as RequestError | null)?.res ?? (error as RequestError | null)?.data?.res;
  if (!response) {
    return false;
  }
  const codes = (response.errors ?? []).map(({ extensions }) => extensions?.code ?? '');
  if (codes.length > 0) {
    return codes.every((code) => TRANSIENT_ERROR_CODES.includes(code));
  }
  return (response.status ?? 0) >= 500;
};

interface ContainerTimelineErrorBoundaryProps {
  children: ReactNode;
  onRetry: () => void;
}

/** Keeps a transient failure to load the events inside the timeline, with a retry. */
export class ContainerTimelineErrorBoundary extends Component<ContainerTimelineErrorBoundaryProps, { error: unknown }> {
  state = { error: null as unknown };

  static getDerivedStateFromError(error: unknown) {
    return { error };
  }

  retry = () => {
    this.props.onRetry();
    this.setState({ error: null });
  };

  render() {
    const { error } = this.state;
    if (!error) {
      return this.props.children;
    }
    if (!isRetryableError(error)) {
      throw error;
    }
    return <ContainerTimelineErrorState onRetry={this.retry} />;
  }
}

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
