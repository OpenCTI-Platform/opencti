import React from 'react';
import { useFormatter } from '../../../components/i18n';

type OverridesProps = {
  overrides: ReadonlyArray<{
    entity_type: string;
    max_confidence: number;
  }> | undefined;
};

const Overrides: React.FC<OverridesProps> = ({ overrides }) => {
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

export default Overrides;
