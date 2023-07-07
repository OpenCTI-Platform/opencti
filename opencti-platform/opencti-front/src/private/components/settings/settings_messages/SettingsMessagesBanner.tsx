import { Close } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import makeStyles from '@mui/styles/makeStyles';
import * as R from 'ramda';
import React, { useEffect, useLayoutEffect, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { Theme } from '../../../../components/Theme';
import { generateBannerMessageColors } from '../../../../utils/Colors';
import useBus, { dispatch } from '../../../../utils/hooks/useBus';
import useLocalStorage, { MessageFromLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { SettingsMessagesBannerQuery } from './__generated__/SettingsMessagesBannerQuery.graphql';
import { SettingsMessagesBannerSubscription } from './__generated__/SettingsMessagesBannerSubscription.graphql';

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
        color
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
        color
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

const BANNER_LOCAL_STORAGE_KEY = 'banner';
const BANNER_DIV = 'banner_div';

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
const ref = React.createRef<HTMLDivElement>();
export const useSettingsMessagesBannerHeight = () => {
  const [bannerHeight, setBannerHeight] = useState(ref.current?.clientHeight ?? 0);
  useBus(BANNER_LOCAL_STORAGE_KEY, (size: number) => setBannerHeight(size ?? 0));
  return bannerHeight;
};

// -- FUNCTION COMPONENT --

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

  const messagesSettings = (settings.messages ?? []) as MessageFromLocalStorage[];
  const [
    { messages: messagesLocalStorage },
    setMessages,
  ] = useLocalStorage(BANNER_LOCAL_STORAGE_KEY, { messages: messagesSettings });

  let messageToDisplay: MessageFromLocalStorage;
  // Update the local storage when new items are found
  useEffect(() => {
    // 1. New message -> Update local storage
    const messagesUpdated = messagesSettings.map((message) => {
      const messageLocalStorage = messagesLocalStorage?.find((m) => m.id === message.id);
      if (messageLocalStorage) {
        if (messageLocalStorage.updated_at < message.updated_at || messageLocalStorage?.dismissible !== message.dismissible) {
          return { ...message, dismiss: false };
        }
        return messageLocalStorage;
      }
      return { ...message, dismiss: false };
    });
    if (!R.equals(messagesUpdated, messagesLocalStorage)) {
      setMessages({ messages: messagesUpdated });
    }
    [messageToDisplay] = extractMessagesToDisplay(messagesUpdated);
  }, [JSON.stringify(messagesSettings)]);

  // Tell everyone that the new message is displayed
  useLayoutEffect(() => {
    dispatch(BANNER_LOCAL_STORAGE_KEY, ref.current?.clientHeight);
  }, [JSON.stringify(messagesLocalStorage)]);

  // 2. No message
  if (!messagesLocalStorage || messagesLocalStorage.length === 0) {
    return (<></>);
  }

  // 3. Retrieve message to display
  [messageToDisplay] = extractMessagesToDisplay(messagesLocalStorage);
  // 4. Message not activated or dismiss
  if (!messageToDisplay) {
    return (<></>);
  }

  // 5. Message activated and not dismiss
  const handleDismiss = () => {
    const otherMessages = messagesLocalStorage.filter((m) => m.id !== messageToDisplay.id);
    setMessages({ messages: [...otherMessages, { ...messageToDisplay, dismiss: true }] });
  };

  const {
    backgroundColor,
    borderLeft,
    color,
  } = generateBannerMessageColors(messageToDisplay?.color);
  return (
    <div
      ref={ref}
      id={BANNER_DIV}
      className={classes.container}
      style={{
        backgroundColor,
        borderLeft,
      }}
    >
      <div
        className={classes.message}
        style={{ color }}
      >
        {messageToDisplay.message}
      </div>
      {messageToDisplay.dismissible
        && (
          <IconButton
            aria-label="close"
            color="inherit"
            size="small"
            className={classes.button}
            style={{ color }}
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
