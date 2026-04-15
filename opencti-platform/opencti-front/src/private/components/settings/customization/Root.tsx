import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import Loader from '../../../../components/Loader';
import CustomizationMenu from '../CustomizationMenu';
import useGranted, { SETTINGS_SETCUSTOMIZATION } from '../../../../utils/hooks/useGranted';
import useSettingsFallbackUrl from '../../../../utils/hooks/useSettingsFallbackUrl';

const Security = lazy(() => import('../../../../utils/Security'));
const Notifiers = lazy(() => import('../Notifiers'));
const Retention = lazy(() => import('../Retention'));
const Rules = lazy(() => import('../rules/Rules'));
const RootSubType = lazy(() => import('../sub_types/Root'));
const SubTypes = lazy(() => import('../sub_types/SubTypes'));
const DecayRuleTabs = lazy(() => import('../decay/DecayRuleTabs'));
const DecayRule = lazy(() => import('../decay/DecayRule'));
const ExclusionLists = lazy(() => import('../exclusion_lists/ExclusionLists'));
const FintelDesigns = lazy(() => import('../fintel_design/FintelDesigns'));
const FintelDesign = lazy(() => import('../fintel_design/FintelDesign'));

const RootCustomization = () => {
  const fallbackUrl = useSettingsFallbackUrl();
  const isGrantedToCustomization = useGranted([SETTINGS_SETCUSTOMIZATION]);

  if (!isGrantedToCustomization) {
    return <Navigate to={fallbackUrl} />;
  }

  return (
    <>
      <CustomizationMenu />
      <Suspense fallback={<Loader />}>
        <Routes>
          <Route
            path="/"
            element={<Navigate to="/dashboard/settings/customization/entity_types" replace={true} />}
          />
          <Route
            path="/entity_types"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <SubTypes />
              </Security>
            )}
          />
          <Route
            path="/entity_types/:subTypeId/*"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <RootSubType />
              </Security>
            )}
          />
          <Route
            path="/retention"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <Retention />
              </Security>
            )}
          />
          <Route
            path="/rules"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <Rules />
              </Security>
            )}
          />
          <Route
            path="/decay"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <DecayRuleTabs />
              </Security>
            )}
          />
          <Route
            path="/decay/:decayRuleId/*"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <DecayRule />
              </Security>
            )}
          />
          <Route
            path="/exclusion_lists"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <ExclusionLists />
              </Security>
            )}
          />
          <Route
            path="/fintel_designs"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <FintelDesigns />
              </Security>
            )}
          />
          <Route
            path="/fintel_designs/:fintelDesignId/*"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <FintelDesign />
              </Security>
            )}
          />
          <Route
            path="/notifiers"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <Notifiers />
              </Security>
            )}
          />
        </Routes>
      </Suspense>
    </>
  );
};

export default RootCustomization;
