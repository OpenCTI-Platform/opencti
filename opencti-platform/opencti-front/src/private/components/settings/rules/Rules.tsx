import React, { Suspense, useRef, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Alert from '@mui/material/Alert';
import RulesHeader from './RulesHeader';
import { RulesQuery } from './__generated__/RulesQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import useAuth from '../../../../utils/hooks/useAuth';
import { RULE_ENGINE } from '../../../../utils/platformModulesHelper';
import { dayAgo, FIVE_SECONDS, yearsAgo } from '../../../../utils/Time';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import RulesList from './RulesList';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useInterval from '../../../../utils/hooks/useInterval';

export const rulesQuery = graphql`
  query RulesQuery($startDate: DateTime!, $endDate: DateTime) {
    ...RulesHeader_data @arguments(startDate: $startDate, endDate: $endDate)
    ...RulesList_data
  }
`;

interface RulesComponentProps {
  queryRef: PreloadedQuery<RulesQuery>;
  ruleConfiguredCounts: Record<string, RuleConfiguredCounts>;
  onRuleConfiguredCountsChange: (ruleId: string, counts: RuleConfiguredCounts) => void;
}

export interface RuleConfiguredCounts {
  active: number;
  total: number;
}

const RulesComponent = ({
  queryRef,
  ruleConfiguredCounts,
  onRuleConfiguredCountsChange,
}: RulesComponentProps) => {
  const data = usePreloadedQuery(rulesQuery, queryRef);

  return (
    <>
      <RulesHeader
        data={data}
        ruleConfiguredCounts={ruleConfiguredCounts}
      />
      <RulesList
        data={data}
        ruleConfiguredCounts={ruleConfiguredCounts}
        onRuleConfiguredCountsChange={onRuleConfiguredCountsChange}
      />
    </>
  );
};

const Rules = () => {
  const { t_i18n } = useFormatter();
  const { platformModuleHelpers } = useAuth();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Rules Engine | Customization | Settings'));

  const ruleEngineEnabled = platformModuleHelpers.isRuleEngineEnable();

  const breadcrumb = [
    { label: t_i18n('Settings') },
    { label: t_i18n('Customization') },
    { label: t_i18n('Rules engine'), current: true },
  ];

  // Use a ref for variables otherwise we have new variables at each calls (with different seconds)
  // which can cause blink effects with slower networks.
  const queryVariables = useRef({ startDate: yearsAgo(1), endDate: dayAgo() });
  const [ruleConfiguredCounts, setRuleConfiguredCounts] = useState<Record<string, RuleConfiguredCounts>>({});
  const [rulesQueryRef, loadQuery] = useQueryLoader<RulesQuery>(rulesQuery);
  useInterval(
    () => {
      loadQuery(
        queryVariables.current,
        { fetchPolicy: 'store-and-network' },
      );
    },
    FIVE_SECONDS,
  );

  return (
    <div style={{ paddingRight: 200 }} data-testid="rules-page">
      <Breadcrumbs elements={breadcrumb} />

      {!ruleEngineEnabled && (
        <Alert severity="info">
          {t_i18n(platformModuleHelpers.generateDisableMessage(RULE_ENGINE))}
        </Alert>
      )}

      {ruleEngineEnabled && rulesQueryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RulesComponent
            queryRef={rulesQueryRef}
            ruleConfiguredCounts={ruleConfiguredCounts}
            onRuleConfiguredCountsChange={(ruleId, counts) => {
              setRuleConfiguredCounts((previous) => ({
                ...previous,
                [ruleId]: counts,
              }));
            }}
          />
        </Suspense>
      )}
    </div>
  );
};

export default Rules;
