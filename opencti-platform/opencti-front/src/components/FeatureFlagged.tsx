import { ReactNode } from 'react';
import useHelper from '../utils/hooks/useHelper';

interface FeatureFlaggedProps {
  flags: string[];
  Enabled: ReactNode;
  Disabled: ReactNode;
}

/**
 * Utility component to switch between two components based on the value
 * of feature flags. If at least one othe given `flags` is enabled then
 * the `Enabled` component is rendered, otherwise it's the `Disabled` component.
 */
const FeatureFlagged = ({ flags, Enabled, Disabled }: FeatureFlaggedProps) => {
  const { isFeatureEnable } = useHelper();
  const areSomeFeaturesEnabled = flags.some(isFeatureEnable);
  return areSomeFeaturesEnabled ? Enabled : Disabled;
};

export default FeatureFlagged;
