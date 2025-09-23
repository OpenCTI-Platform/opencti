import React, { Suspense, useRef } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Alert from '@mui/material/Alert';
import CustomizationMenu from '@components/settings/CustomizationMenu';
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
  queryRef: PreloadedQuery<RulesQuery>
}

const RulesComponent = ({ queryRef }: RulesComponentProps) => {
  const data = usePreloadedQuery(rulesQuery, queryRef);

  return (
    <>
      <RulesHeader data={data} />
      <RulesList data={data} />
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
      <CustomizationMenu />
      <Breadcrumbs elements={breadcrumb} />

      {!ruleEngineEnabled && (
        <Alert severity="info">
          {t_i18n(platformModuleHelpers.generateDisableMessage(RULE_ENGINE))}
        </Alert>
      )}

      {ruleEngineEnabled && rulesQueryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RulesComponent queryRef={rulesQueryRef} />
        </Suspense>
      )}
    </div>
  );
};

export default Rules;
