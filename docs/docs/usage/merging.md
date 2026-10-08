# Merge objects

## Introduction

OpenCTI’s merge capability stands as a pivotal tool for optimizing threat intelligence data, allowing to consolidate multiple entities of the same type. This mechanism serves as a powerful cleanup tool, harmonizing the platform and unifying scattered information. In this section, we explore the significance of this feature, the process of merging entities, and the strategic considerations involved.

<a id="data-streamlining-section"></a>
## Data streamlining

In the ever-expanding landscape of threat intelligence and the multitude of names chosen by different data sources, data cleanliness is essential. Duplicates and fragmented information hinder efficient analysis. The merge capability is a strategic solution for amalgamating related entities into a cohesive unit. Central to the merging process is the selection of a main entity. This primary entity becomes the anchor, retaining crucial attributes such as name and description. Other entities, while losing specific fields like descriptions, are aliased under the primary entity. This strategic decision preserves vital data while eliminating redundancy.


## Preserving entity relationships

One of the key feature of the merge capability is its ability to preserve relationships. While merging entities, their interconnected relationships are not lost. Instead, they seamlessly integrate into the new, merged entity. This ensures that the intricate web of relationships within the data remains intact, fostering a comprehensive understanding of the threat landscape.


## Conclusion

OpenCTI’s merge capability helps improve the quality of threat intelligence data. By consolidating entities and centralizing relationships, OpenCTI empowers analysts to focus on insights and strategies, unburdened by data silos or fragmentation. However, exercising caution and foresight in the merging process is essential, ensuring a robust and streamlined knowledge basis.


## Additional resources

- **Administration:** To understand how to merge entities and the consideration to take into account, refer to the [Merging](../administration/merging.md) page in the Administration section of the documentation.
- **Deduplication mechanism:** the platform is equipped with [deduplication processes](deduplication.md) that automatically merge data at creation (either manually or by importing data from different sources) if it meets certain conditions.
- **Knowledge curation:** [knowledge curation](knowledge-curation.md) proposes the merges of entities named differently by different sources, and records merges so that they can be reverted (unmerge) during a retention window, except the ones it records as not reversible (such as very large merges, or merges that drop a file with the same name as another one).

The merges an entity took part in are listed in the **Merges** view of its **Changes** tab; open one to see its merge record and, while the merge can be undone, **Undo the merge** ([details](knowledge-curation.md#reversible-merges-and-unmerge)).

![Merges view of the Changes tab of an entity](assets/curation-entity-merges.png)

![Merge record with Undo the merge](assets/curation-merge-record-undo.png)