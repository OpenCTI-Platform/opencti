import React, { ReactNode } from 'react';
import { Link } from 'react-router';
import { DECAY_RULES_PATH, KNOWLEDGE_DECAY_RULE_TAB } from './decayRuleTabState';

// Opens the decay rules page on its Knowledge decay rules tab
const KnowledgeDecayRulesLink = ({ children }: { children: ReactNode }) => (
  <Link to={DECAY_RULES_PATH} state={{ decayTab: KNOWLEDGE_DECAY_RULE_TAB }}>{children}</Link>
);

export default KnowledgeDecayRulesLink;
