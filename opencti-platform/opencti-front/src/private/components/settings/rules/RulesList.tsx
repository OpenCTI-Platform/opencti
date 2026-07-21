import React, { useEffect, useMemo, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Box from '@mui/material/Box';
import RulesListItem from '@components/settings/rules/RulesListItem';
import { useTheme } from '@mui/material/styles';
import RulesStatusChangeDialog, { RulesStatusChangeDialogProps } from '@components/settings/rules/RulesStatusChangeDialog';
import { RulesList_data$data, RulesList_data$key } from './__generated__/RulesList_data.graphql';
import { RULES_LOCAL_STORAGE_KEY } from './rules-utils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

export type Rule = NonNullable<NonNullable<RulesList_data$data['rules']>[number]>;
export type Task = NonNullable<NonNullable<NonNullable<RulesList_data$data['backgroundTasks']>['edges']>[number]>['node'];
export type Work = NonNullable<NonNullable<NonNullable<RulesList_data$data['backgroundTasks']>['edges']>[number]>['node']['work'];

const PROTOTYPE_GENERIC_RULE_ID = 'prototype_generic_relation_chain';
const PROTOTYPE_GENERIC_CREATE_RULE_ID = 'prototype_generic_relation_create';
const GENERAL_PROPAGATION_CATEGORY = 'Testing Concept - General Propagation';

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
  data: RulesList_data$key;
  ruleConfiguredCounts?: Record<string, { active: number; total: number }>;
  onRuleConfiguredCountsChange?: (ruleId: string, counts: { active: number; total: number }) => void;
}

const RulesList = ({
  data,
  ruleConfiguredCounts = {},
  onRuleConfiguredCountsChange,
}: RulesListProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { viewStorage } = usePaginationLocalStorage(RULES_LOCAL_STORAGE_KEY, {});
  const keyword = viewStorage.searchTerm ?? '';

  const [selectedRule, setSelectedRule] = useState<string>();
  const [pendingMutation, setPendingMutation] = useState<RulesStatusChangeDialogProps['status']>();
  const [selectedCategory, setSelectedCategory] = useState<string | undefined>(undefined);

  const { rules, backgroundTasks } = useFragment(fragmentData, data);

  const prototypeGenericRule = useMemo(() => ({
    id: PROTOTYPE_GENERIC_RULE_ID,
    name: 'Generic relationship chain propagation (prototype)',
    description: 'If A - rel -> B and B - rel -> C, then create A - related to -> C with configurable entity and relationship settings.',
    activated: false,
    category: GENERAL_PROPAGATION_CATEGORY,
    display: {
      if: [
        {
          action: null,
          source: 'Entity A',
          source_color: '#ff9800',
          relation: 'Any relationship',
          target: 'Entity B',
          target_color: '#4caf50',
          identifier: null,
          identifier_color: null,
        },
        {
          action: null,
          source: 'Entity B',
          source_color: '#4caf50',
          relation: 'Any relationship',
          target: 'Entity C',
          target_color: '#00bcd4',
          identifier: null,
          identifier_color: null,
        },
      ],
      then: [
        {
          action: 'CREATE',
          source: 'Entity A',
          source_color: '#ff9800',
          relation: 'Related to',
          target: 'Entity C',
          target_color: '#00bcd4',
          identifier: null,
          identifier_color: null,
        },
      ],
    },
  }) as Rule, []);

  const prototypeGenericCreateRule = useMemo(() => ({
    id: PROTOTYPE_GENERIC_CREATE_RULE_ID,
    name: 'Generic relationship propagation and creation (prototype)',
    description: 'If A - rel -> B and B - rel -> C, then create A - [configurable relationship] -> C with configurable filters and a user-defined output relationship.',
    activated: false,
    category: GENERAL_PROPAGATION_CATEGORY,
    display: {
      if: [
        {
          action: null,
          source: 'Entity A',
          source_color: '#ff9800',
          relation: 'Any relationship',
          target: 'Entity B',
          target_color: '#4caf50',
          identifier: null,
          identifier_color: null,
        },
        {
          action: null,
          source: 'Entity B',
          source_color: '#4caf50',
          relation: 'Any relationship',
          target: 'Entity C',
          target_color: '#00bcd4',
          identifier: null,
          identifier_color: null,
        },
      ],
      then: [
        {
          action: 'CREATE',
          source: 'Entity A',
          source_color: '#ff9800',
          relation: 'Configurable relationship',
          target: 'Entity C',
          target_color: '#00bcd4',
          identifier: null,
          identifier_color: null,
        },
      ],
    },
  }) as Rule, []);

  const filteredRules = useMemo(() => {
    const backendRules: Rule[] = (rules ?? []).flatMap((r) => (r ? [r] : []));
    // Hide the backend "Testing" rule set from the prototype UI.
    const visibleBackendRules = backendRules.filter((r) => r.category !== 'Testing');
    const withPrototypes = [...visibleBackendRules];
    if (!withPrototypes.some((r) => r.id === PROTOTYPE_GENERIC_RULE_ID)) {
      withPrototypes.push(prototypeGenericRule);
    }
    if (!withPrototypes.some((r) => r.id === PROTOTYPE_GENERIC_CREATE_RULE_ID)) {
      withPrototypes.push(prototypeGenericCreateRule);
    }
    const filterByKeyword = (p: Rule) => keyword === ''
      || p?.name.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || p?.description.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || p?.category?.toLowerCase().indexOf(keyword.toLowerCase()) !== -1;
    return withPrototypes.filter((r) => filterByKeyword(r));
  }, [rules, keyword, prototypeGenericRule, prototypeGenericCreateRule]);

  const categories = useMemo(() => {
    const setOfCategories = new Set(filteredRules.flatMap((r) => r.category ?? []));
    // Keep the General Propagation testing concept as the final tab.
    return Array.from(setOfCategories).sort((a, b) => {
      if (a === GENERAL_PROPAGATION_CATEGORY) return 1;
      if (b === GENERAL_PROPAGATION_CATEGORY) return -1;
      return a.localeCompare(b);
    });
  }, [filteredRules]);

  useEffect(() => {
    setSelectedCategory((previous) => {
      if (previous && categories.includes(previous)) {
        return previous;
      }
      return categories[0];
    });
  }, [categories]);

  const getRulesByCategory = (cat: string) => filteredRules
    .filter((r) => r.category === cat).sort((a, b) => a.name.localeCompare(b.name));
  const getTasksByRuleId = (ruleId: string) => (backgroundTasks?.edges ?? [])
    .flatMap((e) => (e?.node.rule === ruleId ? e.node : []));

  const getCategoryCounts = (cat: string) => getRulesByCategory(cat).reduce((acc, sectionRule) => {
    const override = ruleConfiguredCounts[sectionRule.id];
    if (override) {
      return {
        active: acc.active + override.active,
        total: acc.total + override.total,
      };
    }
    return {
      active: acc.active + (sectionRule.activated ? 1 : 0),
      total: acc.total + 1,
    };
  }, { active: 0, total: 0 });

  const activeCategory = (selectedCategory && categories.includes(selectedCategory))
    ? selectedCategory
    : categories[0];

  return (
    <div style={{ marginTop: theme.spacing(3) }}>
      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs
          value={activeCategory ?? false}
          onChange={(_, value) => setSelectedCategory(value)}
          variant="scrollable"
          scrollButtons="auto"
        >
          {categories.map((category) => {
            const counts = getCategoryCounts(category);
            return (
              <Tab
                key={category}
                value={category}
                label={`${t_i18n(category)} (${counts.active}/${counts.total})`}
              />
            );
          })}
        </Tabs>
      </Box>
      {activeCategory && (
        <div style={{ marginTop: theme.spacing(2) }}>
          {getRulesByCategory(activeCategory).map((catRule) => (
            <RulesListItem
              key={catRule.id}
              rule={catRule}
              task={getTasksByRuleId(catRule.id)[0]}
              onConfiguredRuleCountsChange={(counts) => onRuleConfiguredCountsChange?.(catRule.id, counts)}
              toggle={() => {
                if (catRule.id === PROTOTYPE_GENERIC_RULE_ID
                  || catRule.id === PROTOTYPE_GENERIC_CREATE_RULE_ID) {
                  return;
                }
                setSelectedRule(catRule.id);
                setPendingMutation(catRule.activated ? 'disable' : 'enable');
              }}
            />
          ))}
        </div>
      )}
      <RulesStatusChangeDialog
        ruleId={selectedRule}
        status={pendingMutation}
        changeStatus={setPendingMutation}
      />
    </div>
  );
};

export default RulesList;
