import React from 'react';
import { useFormatter } from '../../../../components/i18n';

type GroupOverridesProps = {
  overrides: ReadonlyArray<{
    entity_type: string;
    max_confidence: number;
  }> | undefined;
};

const GroupConfidenceOverrides: React.FC<GroupOverridesProps> = ({ overrides }) => {
  const { t_i18n } = useFormatter();
  return overrides?.length ? (
    <div style={{ marginTop: '5px' }}>
      <div>{t_i18n('Max Confidence is overridden for some entity types:')}</div>
      {overrides.map((override, index) => (
        <div key={index}>
          {`- ${t_i18n(`entity_${override.entity_type}`)}: ${override.max_confidence}`}
        </div>
      ))}
    </div>
  ) : null;
};

export default GroupConfidenceOverrides;
