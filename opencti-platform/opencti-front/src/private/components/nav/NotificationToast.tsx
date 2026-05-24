import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { Close, NotificationsOutlined } from '@mui/icons-material';
import {
  Box,
  Paper,
  Stack,
  Typography,
  alpha,
} from '@mui/material';
import { useTheme } from '@mui/styles';
import React, { FunctionComponent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { graphql, useSubscription } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import type { Theme } from '../../../components/Theme';
import { useFormatter } from '../../../components/i18n';
import { fetchQuery } from '../../../relay/environment';
import useGranted, { KNOWLEDGE } from '../../../utils/hooks/useGranted';
import {
  getNotificationToastMessage,
  getNotificationToastTitle,
  getNotificationViewTarget,
} from '../profile/notifications/notificationUtils';
import { NotificationToastInitialQuery$data } from './__generated__/NotificationToastInitialQuery.graphql';
import { NotificationToastLatestQuery$data } from './__generated__/NotificationToastLatestQuery.graphql';
import { NotificationToastNumberSubscription$data } from './__generated__/NotificationToastNumberSubscription.graphql';
import { NotificationToastUnreadIdsQuery$data } from './__generated__/NotificationToastUnreadIdsQuery.graphql';

const MAX_VISIBLE_TOASTS = 4;
const TOAST_DURATION_MS = 20000;

type ToastNotification = NonNullable<
  NonNullable<
    NonNullable<NotificationToastLatestQuery$data['myNotifications']>['edges']
  >[number]
>['node'];

const notificationToastInitialQuery = graphql`
  query NotificationToastInitialQuery {
    myUnreadNotificationsCount
  }
`;

const notificationToastLatestQuery = graphql`
  query NotificationToastLatestQuery($count: Int!) {
    myNotifications(first: $count, orderBy: created, orderMode: desc) {
      edges {
        node {
          id
          name
          is_read
          notification_type
          notification_content {
            title
            events {
              message
              operation
              instance_id
            }
          }
        }
      }
    }
  }
`;

const notificationToastUnreadIdsQuery = graphql`
  query NotificationToastUnreadIdsQuery {
    myNotifications(
      first: 50
      orderBy: created
      orderMode: desc
      filters: {
        mode: and
        filters: [{ key: "is_read", values: ["false"] }]
        filterGroups: []
      }
    ) {
      edges {
        node {
          id
        }
      }
    }
  }
`;

const notificationToastNumberSubscription = graphql`
  subscription NotificationToastNumberSubscription {
    notificationsNumber {
      count
    }
  }
`;

interface NotificationToastItemProps {
  notification: ToastNotification;
  onDismiss: (id: string) => void;
  onView: (notification: ToastNotification) => void;
}

const NotificationToastItem: FunctionComponent<NotificationToastItemProps> = ({
  notification,
  onDismiss,
  onView,
}) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const primaryColor = theme.palette.primary.main ?? theme.palette.text.primary ?? '#1976d2';

  const title = getNotificationToastTitle(notification);
  const rawMessage = getNotificationToastMessage(notification);
  const message = rawMessage === null
    ? t_i18n('Digest with multiple notifiers')
    : rawMessage;

  return (
    <Paper
      elevation={4}
      sx={{
        width: 420,
        maxWidth: 'calc(100vw - 32px)',
        p: 2,
        borderRadius: 2,
        backgroundColor: theme.palette.background.paper,
      }}
    >
      <Stack spacing={1.5}>
        <Stack direction="row" spacing={1.5} alignItems="flex-start">
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: 40,
              height: 40,
              borderRadius: '50%',
              flexShrink: 0,
              backgroundColor: alpha(primaryColor, 0.12),
              color: primaryColor,
            }}
          >
            <NotificationsOutlined fontSize="small" />
          </Box>
          <Box sx={{ flex: 1, minWidth: 0, pt: 0.25 }}>
            <Typography
              variant="subtitle2"
              fontWeight={600}
              sx={{
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                display: '-webkit-box',
                WebkitLineClamp: 2,
                WebkitBoxOrient: 'vertical',
              }}
            >
              {title || t_i18n('Notification')}
            </Typography>
          </Box>
          <IconButton
            aria-label={t_i18n('Close')}
            size="small"
            onClick={() => onDismiss(notification.id)}
            sx={{ mt: -0.5, mr: -0.5 }}
          >
            <Close fontSize="small" />
          </IconButton>
        </Stack>
        {message && (
          <Typography
            variant="body2"
            color="text.secondary"
            sx={{
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              display: '-webkit-box',
              WebkitLineClamp: 3,
              WebkitBoxOrient: 'vertical',
            }}
          >
            {message}
          </Typography>
        )}
        <Stack direction="row" spacing={1}>
          <Button variant="tertiary" size="small" onClick={() => onView(notification)}>
            {t_i18n('View')}
          </Button>
          <Button variant="tertiary" size="small" onClick={() => onDismiss(notification.id)}>
            {t_i18n('Dismiss')}
          </Button>
        </Stack>
      </Stack>
    </Paper>
  );
};

const extractLatestNotifications = (
  data: NotificationToastLatestQuery$data,
): ToastNotification[] => (
  data.myNotifications?.edges
    ?.map((edge) => edge?.node)
    .filter((node): node is ToastNotification => !!node && !node.is_read) ?? []
);

const NotificationToast: FunctionComponent = () => {
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const hasKnowledgeAccess = useGranted([KNOWLEDGE]);
  const [toasts, setToasts] = useState<ToastNotification[]>([]);
  const dismissTimersRef = useRef<Record<string, ReturnType<typeof setTimeout>>>({});
  const unreadCountRef = useRef<number | null>(null);
  const pendingUnreadCountRef = useRef<number | null>(null);
  const isInitializedRef = useRef(false);

  const clearDismissTimer = useCallback((id: string) => {
    const timer = dismissTimersRef.current[id];
    if (timer) {
      clearTimeout(timer);
      delete dismissTimersRef.current[id];
    }
  }, []);

  const dismissToast = useCallback((id: string) => {
    clearDismissTimer(id);
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, [clearDismissTimer]);

  const scheduleDismiss = useCallback((id: string) => {
    clearDismissTimer(id);
    dismissTimersRef.current[id] = setTimeout(() => {
      dismissToast(id);
    }, TOAST_DURATION_MS);
  }, [clearDismissTimer, dismissToast]);

  const enqueueToast = useCallback((notification: ToastNotification) => {
    setToasts((current) => {
      const withoutDuplicate = current.filter((toast) => toast.id !== notification.id);
      const next = [...withoutDuplicate, notification];
      const trimmed = next.slice(-MAX_VISIBLE_TOASTS);
      const visibleIds = new Set(trimmed.map((toast) => toast.id));
      current.forEach((toast) => {
        if (!visibleIds.has(toast.id)) {
          clearDismissTimer(toast.id);
        }
      });
      return trimmed;
    });
    scheduleDismiss(notification.id);
  }, [clearDismissTimer, scheduleDismiss]);

  const enqueueNotifications = useCallback((notifications: ToastNotification[]) => {
    notifications.forEach((notification) => {
      enqueueToast(notification);
    });
  }, [enqueueToast]);

  const fetchLatestNotifications = useCallback(async (count: number) => {
    const fetchCount = Math.min(Math.max(count, 1), MAX_VISIBLE_TOASTS);
    const data = await fetchQuery(
      notificationToastLatestQuery,
      { count: fetchCount },
    ).toPromise() as NotificationToastLatestQuery$data;
    const notifications = extractLatestNotifications(data);
    enqueueNotifications([...notifications].reverse());
  }, [enqueueNotifications]);

  const syncVisibleToastsWithUnread = useCallback(async () => {
    const data = await fetchQuery(
      notificationToastUnreadIdsQuery,
      {},
    ).toPromise() as NotificationToastUnreadIdsQuery$data;
    const unreadIds = new Set(
      data.myNotifications?.edges
        ?.map((edge) => edge?.node?.id)
        .filter((id): id is string => !!id) ?? [],
    );
    setToasts((current) => {
      const next = current.filter((toast) => unreadIds.has(toast.id));
      current.forEach((toast) => {
        if (!unreadIds.has(toast.id)) {
          clearDismissTimer(toast.id);
        }
      });
      return next;
    });
  }, [clearDismissTimer]);

  const handleUnreadCountChange = useCallback(async (newCount: number) => {
    if (!isInitializedRef.current) {
      pendingUnreadCountRef.current = newCount;
      return;
    }
    const previousCount = unreadCountRef.current ?? 0;
    unreadCountRef.current = newCount;
    const diff = newCount - previousCount;
    if (diff > 0) {
      await fetchLatestNotifications(diff);
      return;
    }
    if (diff < 0) {
      await syncVisibleToastsWithUnread();
    }
  }, [fetchLatestNotifications, syncVisibleToastsWithUnread]);

  useEffect(() => {
    if (!hasKnowledgeAccess) {
      return undefined;
    }
    let isCancelled = false;
    fetchQuery(notificationToastInitialQuery, {})
      .toPromise()
      .then(async (data) => {
        if (isCancelled) {
          return;
        }
        const initialData = data as NotificationToastInitialQuery$data;
        const baselineCount = initialData.myUnreadNotificationsCount ?? 0;
        const pendingCount = pendingUnreadCountRef.current;
        const effectiveCount = pendingCount ?? baselineCount;
        unreadCountRef.current = effectiveCount;
        isInitializedRef.current = true;
        pendingUnreadCountRef.current = null;
        const diff = effectiveCount - baselineCount;
        if (diff > 0) {
          await fetchLatestNotifications(diff);
        }
      });
    return () => {
      isCancelled = true;
    };
  }, [fetchLatestNotifications, hasKnowledgeAccess]);

  useEffect(() => () => {
    Object.values(dismissTimersRef.current).forEach(clearTimeout);
    dismissTimersRef.current = {};
  }, []);

  const handleNotificationsNumberEvent = useCallback(
    (response: NotificationToastNumberSubscription$data | null | undefined | unknown) => {
      const newCount = response
        ? (response as NotificationToastNumberSubscription$data).notificationsNumber?.count
        : null;
      if (newCount === null || newCount === undefined) {
        return;
      }
      void handleUnreadCountChange(newCount);
    },
    [handleUnreadCountChange],
  );

  const subConfig = useMemo(
    () => ({
      subscription: notificationToastNumberSubscription,
      variables: {},
      onNext: handleNotificationsNumberEvent,
    }),
    [handleNotificationsNumberEvent],
  );

  useSubscription(subConfig);

  const handleView = (notification: ToastNotification) => {
    const target = getNotificationViewTarget(notification);
    if (target.type === 'entity') {
      navigate(`/dashboard/id/${target.instanceId}`);
    } else {
      navigate('/dashboard/profile/notifications');
    }
    dismissToast(notification.id);
  };

  if (!hasKnowledgeAccess || toasts.length === 0) {
    return null;
  }

  return (
    <Box
      sx={{
        position: 'fixed',
        bottom: theme.spacing(2),
        right: theme.spacing(2),
        zIndex: theme.zIndex.snackbar,
        display: 'flex',
        flexDirection: 'column-reverse',
        gap: theme.spacing(1.5),
        pointerEvents: 'none',
        '& > *': {
          pointerEvents: 'auto',
        },
      }}
    >
      {toasts.map((notification) => (
        <NotificationToastItem
          key={notification.id}
          notification={notification}
          onDismiss={dismissToast}
          onView={handleView}
        />
      ))}
    </Box>
  );
};

export default NotificationToast;
