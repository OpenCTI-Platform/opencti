import React, { useEffect, useReducer, useRef, useState } from 'react';
import { compose } from 'ramda';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Typography from '@mui/material/Typography';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import inject18n, { useFormatter } from '../../components/i18n';
import { commitLocalUpdate } from '../../relay/environment';
import { ONE_SECOND, formatSeconds, secondsBetweenDates } from '../../utils/Time';
import { SYSTEM_BANNER_HEIGHT } from '../../utils/SystemBanners';

// NOTE: This is a hack that can go away once <TopBar> has been refactored in 5.9.0
// See https://github.com/OpenCTI-Platform/opencti/issues/2796
/**
 * This semaphore creates a lock that prevents multiple IdleTimeoutLockscreen components
 * from creating additional timeout intervals. There are some views in the application
 * that use the TopBar component twice, which then creates two separate instances of this
 * component. Using an incrementing semaphore like this ensures that only one timeout
 * interval is set at any given moment.
 */
let timeoutSemaphore = 0;

/**
 * Gets timeout and banner settings from react relay and return those values.
 */
export function getSettings(callback: (settings: { idleLimit: number, sessionLimit: number, bannerText: string }) => void) {
  commitLocalUpdate((store: RecordSourceSelectorProxy) => {
    const settings = store.getRoot().getLinkedRecord('settings');
    const bannerText = settings ? String(settings.getValue('platform_banner_text')) : '';
    const timeoutMS = settings ? Number(settings.getValue('platform_session_idle_timeout')) : 0; // Default to 0: Disabled
    const sessionMS = settings ? Number(settings.getValue('platform_session_timeout')) : 1200000;
    const idleLimit = timeoutMS ? Math.floor(timeoutMS / ONE_SECOND) : 0;
    const sessionLimit = sessionMS ? Math.floor(sessionMS / ONE_SECOND) : 0;
    if (typeof callback === 'function') {
      callback({ idleLimit, sessionLimit, bannerText });
    }
  });
}

interface TimeoutState {
  idleLimit: number;
  sessionLimit: number;
  idleCount: number | null;
  startDate: Date;
}

type Action =
  | { type: 'count down' }
  | { type: 'set limits', idleLimit: number, sessionLimit: number }
  | { type: 'reset timeout' }
  | { type: 'disable timeout' };

/**
 * Handles various state changes for the timeout counting functionality.
 */
function timeoutReducer(state: TimeoutState, action: Action): TimeoutState {
  const { idleLimit, sessionLimit, idleCount, startDate } = state;
  switch (action.type) {
    case 'count down':
      if (idleCount) {
        return { idleLimit, sessionLimit, idleCount: idleCount - 1, startDate };
      }
      return state;

    case 'set limits':
      return { idleLimit: action.idleLimit, sessionLimit: action.sessionLimit, idleCount, startDate };

    case 'reset timeout':
      return { idleLimit, sessionLimit, idleCount: sessionLimit, startDate: new Date() };

    case 'disable timeout':
      return { idleLimit: 0, sessionLimit: 0, idleCount: null, startDate: new Date() };

    default:
      return state;
  }
}

/**
 * Redirects to the Dashboard Homepage, flagging the user as being expired.
 */
function redirectToDashboard(handleLogout:(url?: string) => void) {
  const getUrl = window.location;
  handleLogout(`${getUrl.protocol}//${getUrl.host}/dashboard?ExpiredSession=1`);
}

interface IdleTimeoutLockscreenProps {
  handleLogout: (url?: string) => void;
}

const IdleTimeoutLockscreen: React.FunctionComponent<IdleTimeoutLockscreenProps> = ({
  handleLogout,
}) => {
  const { t } = useFormatter();
  const [systemBannersOffset, setSystemBannersOffset] = useState(0);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [state, dispatch] = useReducer(timeoutReducer, { idleLimit: 0, sessionLimit: 0, idleCount: null, startDate: new Date() });
  const [resetCounter, triggerReset] = useState(false);
  const interval = useRef<NodeJS.Timer | null>(null);

  /**
   * Decrements the idle timeout counter by one until it is zero.
   */
  function onCountdown() {
    dispatch({ type: 'count down' });
  }

  /**
   * Clears the timeout interval when restarting a count or unmounting the component.
   */
  function clearTimeoutInterval() {
    if (interval.current) {
      clearInterval(interval.current);
      interval.current = null;
    }
  }

  /**
   * Resets the idle timeout counter, but only if the dialog has been closed.
   */
  function resetIdleTimeout() {
    if (dialogOpen) return; // Don't touch the timeout counter if the dialog is still open
    if (state.sessionLimit > 0) {
      dispatch({ type: 'reset timeout' });
    }
  }

  /**
   * Locks the application screen by opening a dialog which blurs the current application view.
   */
  function lockScreen() {
    setDialogOpen(true);
  }

  /**
   * Unlocks the application screen by closing the dialog and refreshes the session.
   */
  function unlockScreen() {
    setDialogOpen(false);
  }

  /**
   * Disables timeout functionality on this page.
   */
  function disableTimeout() {
    clearTimeoutInterval();
    dispatch({ type: 'disable timeout' });
    unlockScreen();
  }

  /**
   * Triggers a reset of the idle timeout counter, usually when a click event occurs.
   */
  function resetTimeout() {
    triggerReset(true);
  }

  /**
   * Watches dialogOpen state to reset the idle counter when the dialog closes.
   */
  useEffect(() => {
    if (!dialogOpen && state.idleCount) {
      resetIdleTimeout();
    }
  }, [dialogOpen]);

  /**
   * Detects the mounting of the component, similar to componentWillMount() in class component.
   */
  useEffect(() => {
    // NOTE: This is a hack that can go away once <TopBar> has been refactored in 5.9.0
    timeoutSemaphore += 1;
    if (timeoutSemaphore > 1) {
      return;
    }

    // Update state from settings values stored in react relay
    getSettings(({ idleLimit, sessionLimit, bannerText }) => {
      setSystemBannersOffset(bannerText ? SYSTEM_BANNER_HEIGHT : 0);
      dispatch({ type: 'set limits', idleLimit, sessionLimit });
    });

    // Reset the timeout counter every time the user clicks anything in the application
    document.body.addEventListener('click', resetTimeout);

    // Cleanup of this component, similar to componentWillUnmount() in class component
    // eslint-disable-next-line consistent-return
    return () => {
      clearTimeoutInterval();
      // Removing event listeners when the component unmounts is good practice
      document.body.removeEventListener('click', resetTimeout);
      // NOTE: This is a hack that can go away once <TopBar> has been refactored in 5.9.0
      timeoutSemaphore -= 1;
    };
  }, []);

  /**
   * Watches resetCounter trigger state, should only be called by the document.body click listener.
   */
  useEffect(() => {
    if (resetCounter === true) {
      resetIdleTimeout();
      triggerReset(false);
    }
  }, [resetCounter]);

  /**
   * Watches for sessionLimit state change, should only change once when the component loads.
   */
  useEffect(() => {
    if (state.sessionLimit > 0) {
      resetIdleTimeout();
      interval.current = setInterval(onCountdown, ONE_SECOND);
    }
  }, [state.sessionLimit]);

  /**
   * Watches for idleCount change and takes action if timeout limits have been reached.
   */
  useEffect(() => {
    if (state.idleCount === null) return; // Skip further processing of idleCount if it is unset

    const secondsBetween = secondsBetweenDates(state.startDate, new Date());
    // Ensure that the user is logged out if the page has been open longer than the session allows
    if (
      secondsBetween >= state.sessionLimit
      || (state.idleCount !== null && state.idleCount !== undefined && state.idleCount <= 0 && dialogOpen)
    ) {
      redirectToDashboard(handleLogout);
    }
    // Lock the screen for the remaining session time
    if (!dialogOpen && secondsBetween >= state.idleLimit && secondsBetween < state.sessionLimit) {
      lockScreen();
    }
  }, [state.idleCount]);

  // NOTE: The timeout semaphore is a hack that can go away once <TopBar> has been refactored in 5.9.0
  return timeoutSemaphore === 1 ? (
    <Dialog
      open={dialogOpen}
      onClose={() => { }}
      disableEscapeKeyDown={true}
      maxWidth='sm'
      PaperProps={{ elevation: 1 }}
      sx={{
        backdropFilter: 'blur(15px)',
        marginTop: `${systemBannersOffset}px`,
        height: `calc(100% - ${systemBannersOffset * 2}px)`,
      }}
    >
      <DialogTitle sx={{ textAlign: 'center' }}>
        {t('Session Timeout')}
      </DialogTitle>
      <DialogContent>
        <Typography variant='body1'>
          {t('You will be automatically logged out in')}
        </Typography>
        <Typography variant='h6' sx={{ width: '100%', textAlign: 'center' }}>
          {formatSeconds(state.idleCount ?? 0)}
        </Typography>
        <Typography variant='body1'>
          {t('Select CONTINUE to keep working or select lOGOUT to terminate your session.')}
        </Typography>
      </DialogContent>
      <DialogActions
        sx={{
          width: '100%',
          display: 'flex',
          justifyContent: 'space-between',
        }}
      >
        <Button color='secondary' onClick={() => handleLogout()}>
          {t('Logout')}
        </Button>
        <Button size='small' onClick={() => disableTimeout()}>
          {t('Disable timeout on this page')}
        </Button>
        <Button color='primary' onClick={() => unlockScreen()}>
          {t('Continue')}
        </Button>
      </DialogActions>
    </Dialog>
  ) : null;
};

export default compose(inject18n)(IdleTimeoutLockscreen);
