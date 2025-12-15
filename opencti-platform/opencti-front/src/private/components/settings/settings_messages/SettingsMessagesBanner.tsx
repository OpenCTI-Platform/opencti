import { Close } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import makeStyles from '@mui/styles/makeStyles';
import * as R from 'ramda';
import React, { useEffect, useLayoutEffect, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import type { Theme } from '../../../../components/Theme';
import { generateBannerMessageColors } from '../../../../utils/Colors';
import useBus, { dispatch } from '../../../../utils/hooks/useBus';
import useLocalStorage from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { SettingsMessagesBannerQuery } from './__generated__/SettingsMessagesBannerQuery.graphql';
import { MessageFromLocalStorage } from '../../../../utils/hooks/useLocalStorageModel';
import { isEmptyField } from '../../../../utils/utils';
import { extractUrlsFromText } from '../../../../utils/String';

export const settingsMessagesQuery = graphql`
  query SettingsMessagesBannerQuery {
    settings {
      id
      platform_messages {
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
      platform_messages {
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

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    position: 'fixed',
    zIndex: 1202,
    backgroundColor: '#ffecb3',
    borderLeft: '8px solid #ffc107',
    color: '#000000',
    width: '100%',
    padding: 4,
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
    top: '1px',
    right: '8px',
  },
}));

const BANNER_LOCAL_STORAGE_KEY = 'banner';
const BANNER_DIV = 'banner_div';

// -- UTILS --

const isDisplayMessage = (messageFromLocalStorage: MessageFromLocalStorage) => {
  // Message not activated or already dismiss
  if (
    !messageFromLocalStorage
    || !messageFromLocalStorage.activated
    || messageFromLocalStorage.dismiss
  ) {
    return false;
  }

  return true;
};

const extractMessagesToDisplay = (
  messagesFromLocalStorage: MessageFromLocalStorage[],
) => {
  return (messagesFromLocalStorage ?? [])
    .filter((m) => isDisplayMessage(m))
    .sort((m1, m2) => {
      if (m1.dismissible === m2.dismissible) {
        return 0;
      }
      return m1.dismissible ? -1 : 1;
    });
};

const ref = React.createRef<HTMLDivElement>();
export const useSettingsMessagesBannerHeight = () => {
  const [bannerHeight, setBannerHeight] = useState<number>(
    ref.current?.clientHeight as number ?? 0,
  );
  useBus(
    `${BANNER_LOCAL_STORAGE_KEY}_bus`,
    (size: number) => {
      if ((size != null || bannerHeight != null) && bannerHeight !== size) {
        setBannerHeight(size ?? 0);
      }
    },
    [bannerHeight],
  );
  // At first render, some component might have finished their render while settings message send the dispatch.
  if (bannerHeight !== ref.current?.clientHeight && ref.current?.clientHeight != null) {
    setBannerHeight(ref.current?.clientHeight as number);
  }
  return isEmptyField(bannerHeight) ? 0 : bannerHeight;
};

// -- FUNCTION COMPONENT --

const SettingsMessagesBannerComponent = ({
  queryRef,
}: {
  queryRef: PreloadedQuery<SettingsMessagesBannerQuery>;
}) => {
  const classes = useStyles();
  const { settings } = usePreloadedQuery<SettingsMessagesBannerQuery>(
    settingsMessagesQuery,
    queryRef,
  );
  const config = useMemo(
    () => ({
      subscription: settingsSubscription,
      variables: { id: settings.id },
    }),
    [settings, settingsSubscription],
  );
  useSubscription(config);
  const messagesSettings = (settings.platform_messages
    ?? []) as MessageFromLocalStorage[];
  const [{ messages: messagesLocalStorage }, setMessages] = useLocalStorage(
    BANNER_LOCAL_STORAGE_KEY,
    { messages: messagesSettings },
    true,
  );
  let messageToDisplay: MessageFromLocalStorage;
  // Update the local storage when new items are found
  useEffect(() => {
    // 1. New message -> Update local storage
    const messagesUpdated = messagesSettings.map((message) => {
      const messageLocalStorage = messagesLocalStorage?.find(
        (m) => m.id === message.id,
      );
      if (messageLocalStorage) {
        if (
          messageLocalStorage.updated_at < message.updated_at
          || messageLocalStorage?.dismissible !== message.dismissible
        ) {
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
    dispatch(`${BANNER_LOCAL_STORAGE_KEY}_bus`, ref.current?.clientHeight);
  }, [JSON.stringify(messagesLocalStorage)]);

  // 2. No message
  if (!messagesLocalStorage || messagesLocalStorage.length === 0) {
    return <></>;
  }
  // 3. Retrieve message to display
  [messageToDisplay] = extractMessagesToDisplay(messagesLocalStorage);
  // 4. Message not activated or dismiss
  if (!messageToDisplay) {
    return <></>;
  }
  // 5. Message activated and not dismiss
  const handleDismiss = () => {
    const otherMessages = messagesLocalStorage.filter(
      (m) => m.id !== messageToDisplay.id,
    );
    setMessages({
      messages: [...otherMessages, { ...messageToDisplay, dismiss: true }],
    });
  };
  const { backgroundColor, borderLeft, color } = generateBannerMessageColors(
    messageToDisplay?.color,
  );

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
      <div className={classes.message} style={{ color }}>
        {extractUrlsFromText(messageToDisplay.message)}
      </div>
      {messageToDisplay.dismissible && (
        <IconButton
          aria-label="close"
          // color="inherit"
          size="small"
          className={classes.button}
          style={{ color }}
          onClick={handleDismiss}
        >
          <Close fontSize="inherit" />
        </IconButton>
      )}
    </div>
  );
};

const SettingsMessagesBanner = () => {
  const queryRef = useQueryLoading<SettingsMessagesBannerQuery>(
    settingsMessagesQuery,
  );
  return queryRef ? (
    <React.Suspense fallback={<span />}>
      <SettingsMessagesBannerComponent queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <span />
  );
};

export default SettingsMessagesBanner;
