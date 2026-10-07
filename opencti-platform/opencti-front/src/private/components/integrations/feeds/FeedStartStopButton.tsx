import React, { useState } from 'react';
import Button from '@common/button/Button';
import type { BuiltInIntegrationKind } from '@components/integrations/available/builtInIntegrations';
import { FEED_MUTATIONS } from './feedMutations';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';

interface FeedStartStopButtonProps {
  kind: BuiltInIntegrationKind;
  id: string;
  running: boolean;
}

// Same primary Start/Stop button as the connector detail page, driven by
// the same per-kind mutations already used by the feed burger menus.
const FeedStartStopButton: React.FC<FeedStartStopButtonProps> = ({ kind, id, running }) => {
  const { t_i18n } = useFormatter();
  const [submitting, setSubmitting] = useState(false);
  const config = FEED_MUTATIONS[kind];

  const handleClick = () => {
    const nextRunning = !running;
    setSubmitting(true);
    const onDone = () => setSubmitting(false);
    if (config.toggleMutation && config.toggleField) {
      commitMutation({
        mutation: config.toggleMutation,
        variables: {
          id,
          input: { key: config.toggleField, value: [String(nextRunning)] },
        },
        onCompleted: onDone,
        onError: onDone,
        updater: undefined,
        optimisticResponse: undefined,
        optimisticUpdater: undefined,
        setSubmitting: undefined,
      });
      return;
    }
    const mutation = nextRunning ? config.startMutation : config.stopMutation;
    if (!mutation) {
      setSubmitting(false);
      return;
    }
    commitMutation({
      mutation,
      variables: { id },
      onCompleted: onDone,
      onError: onDone,
      updater: undefined,
      optimisticResponse: undefined,
      optimisticUpdater: undefined,
      setSubmitting: undefined,
    });
  };

  return (
    <Button
      disabled={submitting}
      color={running ? 'error' : 'primary'}
      onClick={handleClick}
    >
      {t_i18n(running ? 'Stop' : 'Start')}
    </Button>
  );
};

export default FeedStartStopButton;
