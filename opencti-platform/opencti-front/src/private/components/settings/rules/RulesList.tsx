import React, { useEffect, useMemo, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Typography from '@mui/material/Typography';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import { ExpandMore } from '@mui/icons-material';
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
  const [expandedCategories, setExpandedCategories] = useState<Record<string, boolean>>({});

  const { rules, backgroundTasks } = useFragment(fragmentData, data);

  const prototypeGenericRule = useMemo(() => ({
    id: PROTOTYPE_GENERIC_RULE_ID,
    name: 'Generic relationship chain propagation (prototype)',
    description: 'If A - rel -> B and B - rel -> C, then create A - rel -> C with configurable filters and output relation settings.',
    activated: false,
    category: 'General propagation',
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

  const filteredRules = useMemo(() => {
    const backendRules: Rule[] = (rules ?? []).flatMap((r) => (r ? [r] : []));
    const rulesWithPrototype = backendRules.some((r) => r.id === PROTOTYPE_GENERIC_RULE_ID)
      ? backendRules
      : [...backendRules, prototypeGenericRule];
    const filterByKeyword = (p: Rule) => keyword === ''
      || p?.name.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || p?.description.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || p?.category?.toLowerCase().indexOf(keyword.toLowerCase()) !== -1;
    return rulesWithPrototype.filter((r) => filterByKeyword(r));
  }, [rules, keyword, prototypeGenericRule]);

  const categories = useMemo(() => {
    const setOfCategories = new Set(filteredRules.flatMap((r) => r.category ?? []));
    return Array.from(setOfCategories).sort();
  }, [filteredRules]);

  useEffect(() => {
    setExpandedCategories((previous) => {
      const next: Record<string, boolean> = {};
      categories.forEach((category) => {
        next[category] = previous[category] ?? false;
      });
      return next;
    });
  }, [categories]);

  const getRulesByCategory = (cat: string) => filteredRules
    .filter((r) => r.category === cat).sort((a, b) => a.name.localeCompare(b.name));
  const getTasksByRuleId = (ruleId: string) => (backgroundTasks?.edges ?? [])
    .flatMap((e) => (e?.node.rule === ruleId ? e.node : []));

  return (
    <div style={{ marginTop: theme.spacing(3) }}>
      {categories.map((category) => (
        (() => {
          const sectionRules = getRulesByCategory(category);
          const sectionCounts = sectionRules.reduce((acc, sectionRule) => {
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
          return (
            <Accordion
              key={category}
              expanded={expandedCategories[category] ?? true}
              onChange={(_, expanded) => {
                setExpandedCategories((previous) => ({
                  ...previous,
                  [category]: expanded,
                }));
              }}
              disableGutters
              slotProps={{ transition: { unmountOnExit: false } }}
              sx={{ boxShadow: 'none', background: 'transparent', '&:before': { display: 'none' } }}
            >
              <AccordionSummary
                expandIcon={<ExpandMore />}
                sx={{
                  px: 0,
                  borderTop: (t) => `1px solid ${t.palette.divider}`,
                  borderBottom: (t) => `1px solid ${t.palette.divider}`,
                  minHeight: 56,
                  '&.Mui-expanded': {
                    minHeight: 56,
                  },
                  '& .MuiAccordionSummary-content.Mui-expanded': {
                    margin: '12px 0',
                  },
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%', paddingRight: theme.spacing(1) }}>
                  <Typography variant="h2" gutterBottom={false} sx={{ marginBottom: 0 }}>
                    {t_i18n(category)}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {sectionCounts.active}
                    /
                    {sectionCounts.total}
                    {' '}
                    {t_i18n('active')}
                  </Typography>
                </div>
              </AccordionSummary>
              <AccordionDetails sx={{ px: 0, pt: 1 }}>
                {sectionRules.map((catRule) => (
                  <RulesListItem
                    key={catRule.id}
                    rule={catRule}
                    task={getTasksByRuleId(catRule.id)[0]}
                    onConfiguredRuleCountsChange={(counts) => onRuleConfiguredCountsChange?.(catRule.id, counts)}
                    toggle={() => {
                      if (catRule.id === PROTOTYPE_GENERIC_RULE_ID) {
                        return;
                      }
                      setSelectedRule(catRule.id);
                      setPendingMutation(catRule.activated ? 'disable' : 'enable');
                    }}
                  />
                ))}
              </AccordionDetails>
            </Accordion>
          );
        })()
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
