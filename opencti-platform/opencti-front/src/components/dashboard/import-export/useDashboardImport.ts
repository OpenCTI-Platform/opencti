import { BaseSyntheticEvent, useCallback, useRef } from 'react';
import { MESSAGING$ } from '../../../relay/environment';

const useDashboardImport = ({ onImport }: {
  onImport: (file: File) => Promise<void>;
}) => {
  const inputRef = useRef<HTMLInputElement | null>(null);

  const onChange = (event: BaseSyntheticEvent) => {
    const importedFile = event.target.files[0];
    onImport(importedFile)
      .catch((error) => {
        // a rejection without payload follows a request error the mutation already reported
        if (!error?.res) return;
        MESSAGING$.notifyCustomRelayError(error, {
          name: 'An unknown error has occurred! Please try again later.',
        });
      })
      .finally(() => {
        if (inputRef.current) {
          inputRef.current.value = '';
        }
      });
  };

  const handleImport = useCallback(() => inputRef.current?.click(), []);
  return { onChange, handleImport, inputRef };
};

export default useDashboardImport;
