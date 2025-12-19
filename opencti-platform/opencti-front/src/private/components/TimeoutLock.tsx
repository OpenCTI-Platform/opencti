import React, { useEffect, useReducer, useRef, useState } from 'react';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContentText from '@mui/material/DialogContentText';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../components/i18n';
import { formatSeconds, ONE_SECOND, secondsBetweenDates } from '../../utils/Time';
import useAuth from '../../utils/hooks/useAuth';
import { APP_BASE_PATH } from '../../relay/environment';

/**
 * Gets timeout and banner settings from react relay and return those values.
 */
interface TimeoutState {
  idleLimit: number;
  sessionLimit: number;
  idleCount: number | null;
  startDate: Date;
  startDateEpoch: number;
}

type Action = { type: 'count down' } | { type: 'reset timeout' };

/**
 * Handles various state changes for the timeout counting functionality.
 */
const timeoutReducer = (state: TimeoutState, action: Action): TimeoutState => {
  const { idleLimit, sessionLimit } = state;
  let { idleCount, startDate, startDateEpoch } = state;
  if (idleCount === null) {
    idleCount = sessionLimit;
  }
  const timeoutJSON = localStorage.getItem('lockoutTracker');
  if (timeoutJSON !== null) {
    const timeoutData = JSON.parse(timeoutJSON);
    startDate = timeoutData.startDate;
    startDateEpoch = timeoutData.startDateEpoch;
    idleCount = sessionLimit - (Date.now() - timeoutData.startDateEpoch) / 1000;
  } else {
    // If timeout start not yet initialize, setup the local storage
    const newTimeItem = { startDate: new Date(), startDateEpoch: Date.now() };
    localStorage.setItem('lockoutTracker', JSON.stringify(newTimeItem));
    idleCount -= 1;
  }
  // Handle actions
  if (action.type === 'count down') {
    if (idleCount) {
      return { idleLimit, sessionLimit, idleCount, startDate, startDateEpoch };
    }
    return state;
  }
  if (action.type === 'reset timeout') {
    const newTimeItem = { startDate: new Date(), startDateEpoch: Date.now() };
    localStorage.setItem('lockoutTracker', JSON.stringify(newTimeItem));
    return {
      idleLimit,
      sessionLimit,
      idleCount: sessionLimit,
      startDate: newTimeItem.startDate,
      startDateEpoch: newTimeItem.startDateEpoch,
    };
  }
  return state;
};

const TimeoutLock: React.FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const {
    bannerSettings: { bannerHeightNumber, idleLimit, sessionLimit },
  } = useAuth();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [state, dispatch] = useReducer(timeoutReducer, {
    idleLimit,
    sessionLimit,
    idleCount: null,
    startDate: new Date(),
    startDateEpoch: Date.now(),
  });
  const [resetCounter, triggerReset] = useState(false);
  const interval = useRef<NodeJS.Timeout | null>(null);

  const navigate = useNavigate();

  /**
   * Decrements the idle timeout counter by one until it is zero.
   */
  const onCountdown = () => {
    dispatch({ type: 'count down' });
  };

  /**
   * Clears the timeout interval when restarting a count or unmounting the component.
   */
  const clearTimeoutInterval = () => {
    if (interval.current) {
      clearInterval(interval.current);
      interval.current = null;
    }
  };

  /**
   * Resets the idle timeout counter, but only if the dialog has been closed.
   */
  const resetIdleTimeout = () => {
    if (dialogOpen) return; // Don't touch the timeout counter if the dialog is still open
    if (state.sessionLimit > 0) {
      dispatch({ type: 'reset timeout' });
    }
  };

  /**
   * Locks the application screen by opening a dialog which blurs the current application view.
   *
   * Note: Blurred tabs will remain blurred until either "Continue" is confirmed or session is logged out
   *       If you have multiple tabs open, and the user confirms "Continue" in one tab, the timer on the other
   *       tabs will update but the screen will remain blurred until the user confirms the "Continue" for
   *       that window/tab. This is an intentional security constraint.
   */
  const lockScreen = () => {
    setDialogOpen(true);
  };

  /**
   * Going to /logout disconnects the user from the platform (see backend middleware).
   * Referrer is kept so user will be redirected there on next login.
   */
  const handleLogout = () => {
    navigate(`${APP_BASE_PATH}/logout`);
  };

  /**
   * Unlocks the application screen by closing the dialog, un-blurring screen, and refreshes the session.
   *
   * Note: Blurred tabs will remain blurred until either "Continue" is confirmed or session is logged out
   *       If you have multiple tabs open, and the user confirms "Continue" in one tab, the timer on the other
   *       tabs will update but the screen will remain blurred until the user confirms the "Continue" for
   *       that window/tab. This is an intentional security constraint.
   */
  const unlockScreen = () => {
    setDialogOpen(false);
    const newTimeItem = { startDate: new Date(), startDateEpoch: Date.now() };
    localStorage.setItem('lockoutTracker', JSON.stringify(newTimeItem));
  };

  /**
   * Triggers a reset of the idle timeout counter, usually when a click event occurs.
   */
  const resetTimeout = () => {
    triggerReset(true);
  };

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
    // Reset the timeout counter every time the user clicks anything in the application
    document.body.addEventListener('click', resetTimeout);

    // Cleanup of this component, similar to componentWillUnmount() in class component

    return () => {
      clearTimeoutInterval();
      // Removing event listeners when the component unmounts is good practice
      document.body.removeEventListener('click', resetTimeout);
    };
  }, []);

  /**
   * Watches resetCounter trigger state, should only be called by the document.body click listener.
   */
  useEffect(() => {
    if (resetCounter) {
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
    if (state.idleCount === null) {
      return; // Skip further processing of idleCount if it is unset
    }
    const secondsBetween = secondsBetweenDates(state.startDate, new Date());
    // Ensure that the user is logged out if the page has been open longer than the session allows
    if (
      secondsBetween >= state.sessionLimit
      || (state.idleCount !== undefined && state.idleCount <= 0 && dialogOpen)
    ) {
      handleLogout();
    }
    // Lock the screen for the remaining session time
    if (secondsBetween >= state.idleLimit && secondsBetween < state.sessionLimit) {
      lockScreen();
    } else { // To handle close on different tab
      setDialogOpen(false);
    }
  }, [state.idleCount]);

  return (
    <Dialog
      open={dialogOpen}
      onClose={() => {
      }}
      disableEscapeKeyDown={true}
      maxWidth="sm"
      slotProps={{ paper: { elevation: 1 } }}
      sx={{
        backdropFilter: 'blur(15px)',
        marginTop: `${bannerHeightNumber}px`,
        height: `calc(100% - ${bannerHeightNumber * 2}px)`,
      }}
    >
      <DialogTitle sx={{ textAlign: 'center' }}>
        {t_i18n('Session timeout in')}&nbsp;
        <strong>{formatSeconds(state.idleCount ?? 0)}</strong>
      </DialogTitle>
      <DialogContent>
        <DialogContentText sx={{ textAlign: 'center' }}>
          {t_i18n('You will be automatically logged out at end of the timer.')}
          <br />
          {t_i18n('Select')} <code>{t_i18n('CONTINUE')}</code>{' '}
          {t_i18n('to keep working or select')} <code>{t_i18n('LOGOUT')}</code>{' '}
          {t_i18n('to terminate your session.')}
        </DialogContentText>
      </DialogContent>
      <DialogActions
        sx={{
          width: '100%',
          display: 'flex',
          justifyContent: 'space-between',
        }}
      >
        <Button variant="secondary" onClick={() => handleLogout()}>
          {t_i18n('Logout')}
        </Button>
        <Button onClick={() => unlockScreen()}>
          {t_i18n('Continue')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default TimeoutLock;
