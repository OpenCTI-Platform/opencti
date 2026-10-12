import { registerFieldAuthorityResolver, registerMergeRecorder } from '../../database/merge-hooks';
import { curationMergeRecorder } from './curation-merge-record';
import { curationFieldAuthorityResolver } from './curation-field-authority';

// Reversible merges: every merge of the platform is recorded so that it can be reverted.
registerMergeRecorder(curationMergeRecorder);
// Field authority merge policy consulted in upsert resolution (no-op until rules are configured).
registerFieldAuthorityResolver(curationFieldAuthorityResolver);
