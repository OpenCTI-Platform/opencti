import { createContext, ReactNode } from 'react';

// What a non-admin gets when activating an Enterprise Edition gate (the feedback form).
// Provided by the app instead of imported by the gate: that form renders a markdown field,
// whose AI button uses the gate.
export type EERequest = (open: boolean, onClose: () => void, feature?: string) => ReactNode;

const EERequestContext = createContext<EERequest | undefined>(undefined);

export default EERequestContext;
