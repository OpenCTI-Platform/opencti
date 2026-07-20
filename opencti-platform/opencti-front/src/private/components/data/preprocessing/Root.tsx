import React from 'react';
import { Route, Routes, useParams } from 'react-router-dom';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import PreprocessingRulePage from './PreprocessingRulePage';

const RootPreprocessingRule = () => {
  const { ruleId } = useParams();
  if (!ruleId) return <ErrorNotFound />;
  return (<Routes><Route path="/" element={<PreprocessingRulePage ruleId={ruleId} />} /></Routes>);
};
export default RootPreprocessingRule;
