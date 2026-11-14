import { createContext, type ReactNode, useContext } from 'react';

/** The registry entry, a Defense area or a Curation tab, whose content is on screen. */
export interface HubEntry {
  /** English source string, translated where it is shown. */
  label: string;
  /** English source string: the question the entry answers. */
  description?: string;
  icon?: ReactNode;
}

export const HubEntryContext = createContext<HubEntry | null>(null);

/** The entry the hub is rendering, or null outside a hub. */
export const useHubEntry = (): HubEntry | null => useContext(HubEntryContext);
