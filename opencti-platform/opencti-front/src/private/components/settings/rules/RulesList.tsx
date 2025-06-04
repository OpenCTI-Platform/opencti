import React, { useMemo, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Typography from '@mui/material/Typography';
import RulesListItem from '@components/settings/rules/RulesListItem';
import { useTheme } from '@mui/material/styles';
import RulesStatusChangeDialog, { RulesStatusChangeDialogProps } from '@components/settings/rules/RulesStatusChangeDialog';
import { RulesList_data$data, RulesList_data$key } from './__generated__/RulesList_data.graphql';
import { RULES_LOCAL_STORAGE_KEY } from './rules-utils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

export type Rule = NonNullable<RulesList_data$data['rules']>[number];
export type Task = NonNullable<NonNullable<NonNullable<RulesList_data$data['backgroundTasks']>['edges']>[number]>['node'];
export type Work = NonNullable<NonNullable<NonNullable<RulesList_data$data['backgroundTasks']>['edges']>[number]>['node']['work'];

const fragmentData = graphql`
  fragment RulesList_data on Query {
    rules {
      id
      name
      description
      activated
      category
      display {
        if {
          action
          source
          source_color
          relation
          target
          target_color
          identifier
          identifier_color
        }
        then {
          action
          source
          source_color
          relation
          target
          target_color
          identifier
          identifier_color
        }
      }
    }
    backgroundTasks(
      orderBy: created_at
      orderMode: desc
      filters: {
        mode: and,
        filters: [{ key: "type", values: ["RULE"] }]
        filterGroups: []
      }
    ) {
      edges {
        node {
          id
          created_at
          task_expected_number
          task_processed_number
          completed
          ... on RuleTask {
            rule
            enable
          }
          work {
            id
            connector {
              name
            }
            user {
              name
            }
            completed_time
            received_time
            tracking {
              import_expected_number
              import_processed_number
            }
            messages {
              timestamp
              message
            }
            errors {
              timestamp
              message
            }
            status
            timestamp
            draft_context
          }
          ... on RuleTask {
            rule
            enable
          }
        }
      }
    }
  }
`;

interface RulesListProps {
  data: RulesList_data$key
}

const RulesList = ({ data }: RulesListProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { viewStorage } = usePaginationLocalStorage(RULES_LOCAL_STORAGE_KEY, {});
  const keyword = viewStorage.searchTerm ?? '';

  const [selectedRule, setSelectedRule] = useState<string>();
  const [pendingMutation, setPendingMutation] = useState<RulesStatusChangeDialogProps['status']>();

  const { rules, backgroundTasks } = useFragment(fragmentData, data);

  const filteredRules = useMemo(() => {
    const filterByKeyword = (p: Rule) => keyword === ''
      || p?.name.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || p?.description.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || p?.category?.toLowerCase().indexOf(keyword.toLowerCase()) !== -1;
    return (rules ?? []).flatMap((r) => (!r || !filterByKeyword(r) ? [] : r));
  }, [rules, viewStorage]);

  const categories = useMemo(() => {
    const setOfCategories = new Set(filteredRules.flatMap((r) => r.category ?? []));
    return Array.from(setOfCategories).sort();
  }, [filteredRules]);

  const getRulesByCategory = (cat: string) => filteredRules
    .filter((r) => r.category === cat).sort((a, b) => a.name.localeCompare(b.name));
  const getTasksByRuleId = (ruleId: string) => (backgroundTasks?.edges ?? [])
    .flatMap((e) => (e?.node.rule === ruleId ? e.node : []));

  return (
    <div style={{ marginTop: theme.spacing(3) }}>
      {categories.map((category) => (
        <div key={category}>
          <Typography variant="h2" gutterBottom={true} sx={{ marginBottom: 2 }}>
            {t_i18n(category)}
          </Typography>
          {getRulesByCategory(category).map((catRule) => (
            <RulesListItem
              key={catRule.id}
              rule={catRule}
              task={getTasksByRuleId(catRule.id)[0]}
              toggle={() => {
                setSelectedRule(catRule.id);
                setPendingMutation(catRule.activated ? 'disable' : 'enable');
              }}
            />
          ))}
        </div>
      ))}
      <RulesStatusChangeDialog
        ruleId={selectedRule}
        status={pendingMutation}
        changeStatus={setPendingMutation}
      />
    </div>
  );
};

export default RulesList;
