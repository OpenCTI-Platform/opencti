import React from 'react';
import EEChip from '@components/common/entreprise_edition/EEChip';

/** The label of an Enterprise Edition field, followed by the EE chip of its feature (shown only in Community Edition). */
const HuntEELabel = ({ label, feature }: { label: string; feature: string }) => (
  <span style={{ display: 'inline-flex', alignItems: 'center' }}>
    {label}
    <EEChip feature={feature} size="sm" />
  </span>
);

export default HuntEELabel;
