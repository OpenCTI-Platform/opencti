import React, { FunctionComponent } from 'react';
import { ReactFlowProvider } from 'reactflow';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { getRule } from './preprocessingStore';
import PreprocessingHeader from './PreprocessingHeader';
import PreprocessingFlow from './PreprocessingFlow';

interface PreprocessingRulePageProps { ruleId: string; }

const PreprocessingRulePage: FunctionComponent<PreprocessingRulePageProps> = ({ ruleId }) => {
  const { t_i18n } = useFormatter();
  const rule = getRule(ruleId);
  if (!rule) return <ErrorNotFound />;
  return (
    <>
      <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Pre-processing'), link: '/dashboard/data/preprocessing' }, { label: rule.name, current: true }]} />
      <PreprocessingHeader ruleId={ruleId} />
      <ReactFlowProvider><PreprocessingFlow ruleId={ruleId} /></ReactFlowProvider>
    </>
  );
};
export default PreprocessingRulePage;
