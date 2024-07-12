import { useEffect, useRef, useState } from 'react';
import { MutationParameters, SelectorStoreUpdater } from 'relay-runtime';
import { UseMutationConfig } from 'react-relay';

interface UseBulkCommitArgs<M extends MutationParameters> {
  commit: (args: UseMutationConfig<M>) => void
  relayUpdater?: SelectorStoreUpdater<M['response']>
}

interface UseBulkCommit_commits<I> {
  inputs: I[]
  onStepError?: (err: Error) => void
  onStepCompleted?: () => void
  onCompleted?: () => void
}

function useBulkCommit<I, M extends MutationParameters>({
  commit,
  relayUpdater,
}: UseBulkCommitArgs<M>) {
  const [count, setCount] = useState(0);
  const [currentCount, setCurrentCount] = useState(0);

  const onBulkCompleted = useRef<UseBulkCommit_commits<I>['onCompleted']>();

  useEffect(() => {
    if (currentCount === count && count !== 0) {
      onBulkCompleted.current?.();
      setCurrentCount(0);
      setCount(0);
    }
  }, [count, currentCount, setCurrentCount, setCount]);

  const bulkCommit = ({
    inputs,
    onStepCompleted,
    onStepError,
    onCompleted,
  }: UseBulkCommit_commits<I>) => {
    onBulkCompleted.current = onCompleted;
    setCount(inputs.length);
    setCurrentCount(0);

    inputs.forEach((input) => {
      commit({
        variables: { input },
        updater: relayUpdater,
        onError: (error) => {
          setCurrentCount((c) => c + 1);
          onStepError?.(error);
        },
        onCompleted: () => {
          setCurrentCount((c) => c + 1);
          onStepCompleted?.();
        },
      });
    });
  };

  return { bulkCommit };
}

export default useBulkCommit;
