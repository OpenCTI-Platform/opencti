# Curation

**Data > Curation** is the data-quality home of your knowledge base. Instead of separate menu entries, the work that keeps the knowledge clean lives in one place, as tabs:

| Tab | What you do there |
| --- | --- |
| Inbox | Review what the curation engine proposes: possible duplicates, conflicting values, objects to merge ([details](knowledge-curation.md#work-the-curation-inbox)). |
| Conflicts | See the attributes your sources disagree on, and which value each source asserts ([details](provenance.md#curation-tabs)). |
| Stale knowledge | Find knowledge whose sources stopped confirming it, according to the knowledge decay rules ([details](provenance.md#curation-tabs)). |
| Merges | Follow the merges that were applied, and undo one when it was wrong ([details](knowledge-curation.md#reversible-merges-and-unmerge)). |
| Knowledge health | Measure the quality of the knowledge base over time ([details](knowledge-curation.md#read-the-knowledge-health-score)). |

## When the entry is shown

- **Curation** appears in the **Data** menu, right after **Relationships**, as soon as one of its tabs is available on your platform.
- Each tab has its own permission check: a tab you are not allowed to use is not listed, and the hub opens the first tab you can use.
- Each tab keeps its own address under `Data > Curation`, so a link to a tab can be bookmarked and shared.

## Related pages

- [Knowledge curation](knowledge-curation.md): the detectors, proposals, reversible merges, policies and Knowledge Health behind the Inbox, Merges and Knowledge health tabs.
- [Provenance](provenance.md): the sources, conflicts and freshness behind the Conflicts and Stale knowledge tabs.
- [Deduplication](deduplication.md): how OpenCTI avoids creating the same object twice.
- [Merge objects](merging.md): merging objects by hand.
- [Data consistency](dataSanityManager.md): consistency checks run by the platform.
