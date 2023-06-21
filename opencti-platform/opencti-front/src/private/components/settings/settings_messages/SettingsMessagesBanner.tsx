import makeStyles from '@mui/styles/makeStyles';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import React, { useEffect, useMemo, useState } from 'react';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { Close } from '@mui/icons-material';
import * as R from 'ramda';
import IconButton from '@mui/material/IconButton';
import { SettingsMessagesBannerSubscription } from './__generated__/SettingsMessagesBannerSubscription.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { SettingsMessagesBannerQuery } from './__generated__/SettingsMessagesBannerQuery.graphql';
import { Theme } from '../../../../components/Theme';

export const settingsMessagesQuery = graphql`
  query SettingsMessagesBannerQuery {
    settings {
      id
      messages {
        id
        message
        activated
        dismissible
        updated_at
      }
    }
  }
`;

const settingsSubscription = graphql`
  subscription SettingsMessagesBannerSubscription($id: ID!) {
    settingsMessages(id: $id) {
      messages {
        id
        message
        activated
        dismissible
        updated_at
      }
    }
  }
`;

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    position: 'fixed',
    zIndex: 1202,
    backgroundColor: '#ffecb3',
    borderLeft: '8px solid #ffc107',
    color: 'black',
    width: '100%',
    padding: theme.spacing(1),
  },
  message: {
    textAlign: 'center',
    marginRight: theme.spacing(1),
    color: '#663c00',
    fontWeight: 500,
  },
  button: {
    color: '#663c00',
    position: 'absolute',
    top: '5px',
    right: '8px',
  },
}));

const BANNER_LOCAL_STORAGE_KEY = 'BANNER';
const BANNER_DIV_KEY = 'BANNER_DIV';
const BANNER_EVENT_KEY = 'BANNER_EVENT';

// -- LOCAL STORAGE --

const getMessagesFromLocalStorage = () => {
  const item = window.localStorage.getItem(BANNER_LOCAL_STORAGE_KEY);
  return item ? JSON.parse(item) : [];
};
const setMessagesToLocalStorage = (messages: MessageFromLocalStorage[]) => {
  window.localStorage.setItem(BANNER_LOCAL_STORAGE_KEY, JSON.stringify(messages));
};
const dispatchEvent = () => {
  window.dispatchEvent(new Event(BANNER_EVENT_KEY));
};

// -- UTILS --

const isDisplayMessage = (messageFromLocalStorage: MessageFromLocalStorage) => {
  // Message not activated or already dismiss
  if (!messageFromLocalStorage || !messageFromLocalStorage.activated || messageFromLocalStorage.dismiss) {
    return false;
  }

  return true;
};

const extractMessagesToDisplay = (messagesFromLocalStorage: MessageFromLocalStorage[]) => {
  return (messagesFromLocalStorage ?? []).filter((m) => isDisplayMessage(m))
    .sort((m1, m2) => {
      if (m1.dismissible === m2.dismissible) {
        return 0;
      }
      return m1.dismissible ? -1 : 1;
    });
};

// Use windows event to react with local storage update
export const useSettingsMessagesBannerHeight = () => {
  const computeBannerHeight = () => {
    const [messageToDisplay] = extractMessagesToDisplay(getMessagesFromLocalStorage());
    if (!messageToDisplay) {
      return 0;
    }
    return document.getElementById(BANNER_DIV_KEY)?.clientHeight ?? 0;
  };

  const [bannerHeight, setBannerHeight] = useState(computeBannerHeight());
  window.addEventListener(BANNER_EVENT_KEY, () => {
    const newBannerHeight = computeBannerHeight();
    if (newBannerHeight !== bannerHeight) {
      setBannerHeight(computeBannerHeight());
    }
  });
  return bannerHeight;
};

// -- FUNCTION COMPONENT --

interface MessageFromLocalStorage {
  id: string
  message: string
  activated: boolean
  dismissible: boolean
  updated_at: Date
  dismiss: boolean
}

const SettingsMessagesBannerComponent = ({
  queryRef,
}: { queryRef: PreloadedQuery<SettingsMessagesBannerQuery> }) => {
  const classes = useStyles();

  const { settings } = usePreloadedQuery<SettingsMessagesBannerQuery>(settingsMessagesQuery, queryRef);
  const config = useMemo<GraphQLSubscriptionConfig<SettingsMessagesBannerSubscription>>(() => ({
    subscription: settingsSubscription,
    variables: { id: settings.id },
  }), [settings, settingsSubscription]);
  useSubscription(config);

  const messagesSettings = settings.messages ?? [];
  const [messagesLocalStorage, setMessagesLocalStorage] = useState<MessageFromLocalStorage[]>(getMessagesFromLocalStorage());

  useEffect((() => {
    dispatchEvent();
  }), [messagesLocalStorage]);

  // 1. No message
  if ((messagesSettings.length ?? 0) === 0) {
    // Reset local storage
    if (messagesLocalStorage.length > 0) {
      setMessagesToLocalStorage([]);
      setMessagesLocalStorage(getMessagesFromLocalStorage());
    }
    return (<></>);
  }

  // 2. New message -> Update local storage
  const messagesUpdated = messagesSettings.map((message) => {
    const messageLocalStorage = messagesLocalStorage.find((m) => m.id === message.id);
    if (messageLocalStorage) {
      if (messageLocalStorage.updated_at < message.updated_at || messageLocalStorage?.dismissible !== message.dismissible) {
        return { ...message, dismiss: false };
      }
      return messageLocalStorage;
    }
    return { ...message, dismiss: false };
  });
  if (!R.equals(messagesUpdated, messagesLocalStorage)) {
    setMessagesToLocalStorage(messagesUpdated);
    setMessagesLocalStorage(getMessagesFromLocalStorage());
  }
  // 3. Retrieve message to display
  const [messageToDisplay] = extractMessagesToDisplay(messagesLocalStorage);

  // 4. Message not activated or dismiss
  if (!messageToDisplay) {
    return (<></>);
  }

  // 5. Message activated and not dismiss
  const handleDismiss = () => {
    const idx = messagesLocalStorage.findIndex((m) => m.id === messageToDisplay.id);
    messagesLocalStorage.splice(idx, 1);
    setMessagesToLocalStorage([...messagesLocalStorage, { ...messageToDisplay, dismiss: true }]);
    setMessagesLocalStorage(getMessagesFromLocalStorage());
  };

  return (
    <div id={BANNER_DIV_KEY} className={classes.container}>
      <div className={classes.message}>{messageToDisplay.message}</div>
      {messageToDisplay.dismissible
        && (
          <IconButton
            aria-label="close"
            color="inherit"
            size="small"
            className={classes.button}
            onClick={handleDismiss}
          >
            <Close fontSize="inherit" />
          </IconButton>
        )
      }
      </div>
  );
};

const SettingsMessagesBanner = () => {
  const queryRef = useQueryLoading<SettingsMessagesBannerQuery>(settingsMessagesQuery);
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <SettingsMessagesBannerComponent queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default SettingsMessagesBanner;
