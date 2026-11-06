import { useContext, useEffect, useMemo, useRef } from 'react';
import { graphql } from 'react-relay';
import { UserContext } from '../../utils/hooks/useAuth';
import useApiMutation from '../../utils/hooks/useApiMutation';
import { isSameListColumnConfig, ListColumnConfig, parseListColumnsConfig } from './dataTableColumnsConfig';
import type { useListColumnsPreferenceMutation } from './__generated__/useListColumnsPreferenceMutation.graphql';

const listColumnsPreferenceMutation = graphql`
  mutation useListColumnsPreferenceMutation($input: [EditInput]!) {
    meEdit(input: $input) {
      id
      list_columns
    }
  }
`;

// Saving is delayed so that resizing a column or several quick changes send a single update.
const SAVE_DELAY = 800;

/**
 * Columns of a list saved in the user profile, so that they follow the user on any browser.
 * Returns the saved configuration of the list and a function saving a new one (undefined goes back to the default).
 * Without a connected user (e.g. public dashboards) or when disabled, nothing is read nor saved.
 */
const useListColumnsPreference = (storageKey: string, enabled: boolean) => {
  const { me } = useContext(UserContext);
  const [commit] = useApiMutation<useListColumnsPreferenceMutation>(listColumnsPreferenceMutation);
  const isEnabled = enabled && !!me;
  const allConfigs = useMemo(() => parseListColumnsConfig(me?.list_columns), [me?.list_columns]);
  const savedConfig = isEnabled ? allConfigs[storageKey] : undefined;

  const savedListColumns = useRef(me?.list_columns);
  savedListColumns.current = me?.list_columns;
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  // The last value sent, as the profile is only refreshed once the update is done.
  const pendingConfig = useRef<{ value: ListColumnConfig[] | undefined } | undefined>(undefined);
  const pendingSave = useRef<() => void>(undefined);
  // Leaving the list before the delay still saves the last change.
  useEffect(() => () => {
    clearTimeout(timer.current);
    pendingSave.current?.();
  }, []);

  const saveConfig = (config: ListColumnConfig[] | undefined) => {
    if (!isEnabled) return;
    const current = pendingConfig.current ? pendingConfig.current.value : savedConfig;
    if (isSameListColumnConfig(current, config) && !!current === !!config) return;
    pendingConfig.current = { value: config };
    clearTimeout(timer.current);
    pendingSave.current = () => {
      pendingSave.current = undefined;
      // Re-read the other lists from the profile at the time of saving: they can have changed meanwhile.
      const { [storageKey]: _, ...otherConfigs } = parseListColumnsConfig(savedListColumns.current);
      const nextConfigs = config ? { ...otherConfigs, [storageKey]: config } : otherConfigs;
      commit({
        variables: { input: [{ key: 'list_columns', value: [JSON.stringify(nextConfigs)] }] },
        onCompleted: () => {
          pendingConfig.current = undefined;
        },
      });
    };
    timer.current = setTimeout(() => pendingSave.current?.(), SAVE_DELAY);
  };

  return { savedConfig, saveConfig, isEnabled };
};

export default useListColumnsPreference;
