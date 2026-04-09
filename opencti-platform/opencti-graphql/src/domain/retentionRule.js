// Re-export from the new module location for backward compatibility
export {
  checkRetentionRule,
  createRetentionRule,
  retentionRuleEditField,
  deleteRetentionRule,
  findById,
  findRetentionRulePaginated,
  listRules,
} from '../modules/retentionRules/retentionRules-domain';
