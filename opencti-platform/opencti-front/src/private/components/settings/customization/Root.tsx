import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import Loader from '../../../../components/Loader';
import CustomizationMenu from '../CustomizationMenu';
import EntryGuard from '../../nav/EntryGuard';
import useFirstVisiblePath from '../../common/menus/useFirstVisiblePath';
import { entriesUnder } from '../../nav/menuEntries';
import useSettingsFallbackUrl from '../useSettingsFallbackUrl';

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

const customizationEntries = entriesUnder('/dashboard/settings/customization');

const RootCustomization = () => {
  const fallbackUrl = useSettingsFallbackUrl();
  const redirect = useFirstVisiblePath(customizationEntries, fallbackUrl);
  return (
    <>
      <Routes>
        <Route
          path="/entity_types/:subTypeId/custom-views/:customViewId"
          element={null}
        />
        <Route
          path="*"
          element={<CustomizationMenu />}
        />
      </Routes>
      <Suspense fallback={<Loader />}>
        <Routes>
          <Route
            path="/"
            element={<Navigate to={redirect} replace={true} />}
          />
          <Route
            path="/entity_types"
            element={(
              <EntryGuard path="/dashboard/settings/customization/entity_types" placeholder={<Navigate to={fallbackUrl} />}>
                <SubTypes />
              </EntryGuard>
            )}
          />
          <Route
            path="/entity_types/:subTypeId/*"
            element={(
              <EntryGuard path="/dashboard/settings/customization/entity_types" placeholder={<Navigate to={fallbackUrl} />}>
                <RootSubType />
              </EntryGuard>
            )}
          />
          <Route
            path="/retention"
            element={(
              <EntryGuard path="/dashboard/settings/customization/retention" placeholder={<Navigate to={fallbackUrl} />}>
                <Retention />
              </EntryGuard>
            )}
          />
          <Route
            path="/rules"
            element={(
              <EntryGuard path="/dashboard/settings/customization/rules" placeholder={<Navigate to={fallbackUrl} />}>
                <Rules />
              </EntryGuard>
            )}
          />
          <Route
            path="/decay"
            element={(
              <EntryGuard path="/dashboard/settings/customization/decay" placeholder={<Navigate to={fallbackUrl} />}>
                <DecayRuleTabs />
              </EntryGuard>
            )}
          />
          <Route
            path="/decay/:decayRuleId/*"
            element={(
              <EntryGuard path="/dashboard/settings/customization/decay" placeholder={<Navigate to={fallbackUrl} />}>
                <DecayRule />
              </EntryGuard>
            )}
          />
          <Route
            path="/exclusion_lists"
            element={(
              <EntryGuard path="/dashboard/settings/customization/exclusion_lists" placeholder={<Navigate to={fallbackUrl} />}>
                <ExclusionLists />
              </EntryGuard>
            )}
          />
          <Route
            path="/fintel_designs"
            element={(
              <EntryGuard path="/dashboard/settings/customization/fintel_designs" placeholder={<Navigate to={fallbackUrl} />}>
                <FintelDesigns />
              </EntryGuard>
            )}
          />
          <Route
            path="/fintel_designs/:fintelDesignId/*"
            element={(
              <EntryGuard path="/dashboard/settings/customization/fintel_designs" placeholder={<Navigate to={fallbackUrl} />}>
                <FintelDesign />
              </EntryGuard>
            )}
          />
          <Route
            path="/notifiers"
            element={(
              <EntryGuard path="/dashboard/settings/customization/notifiers" placeholder={<Navigate to={fallbackUrl} />}>
                <Notifiers />
              </EntryGuard>
            )}
          />
        </Routes>
      </Suspense>
    </>
  );
};

export default RootCustomization;
