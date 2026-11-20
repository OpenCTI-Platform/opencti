# Merge objects

## Introduction

OpenCTI’s merge capability stands as a pivotal tool for optimizing threat intelligence data, allowing to consolidate multiple entities of the same type. This mechanism serves as a powerful cleanup tool, harmonizing the platform and unifying scattered information. In this section, we explore the significance of this feature, the process of merging entities, and the strategic considerations involved.

<a id="data-streamlining-section"></a>
## Data streamlining

In the ever-expanding landscape of threat intelligence and the multitude of names chosen by different data sources, data cleanliness is essential. Duplicates and fragmented information hinder efficient analysis. The merge capability is a strategic solution for amalgamating related entities into a cohesive unit. Central to the merging process is the selection of a main entity. This primary entity becomes the anchor, retaining crucial attributes such as name and description. Other entities, while losing specific fields like descriptions, are aliased under the primary entity. This strategic decision preserves vital data while eliminating redundancy.


## Merge entities

To merge entities, you need the `Merge knowledge` capability (see [Users and Role Based Access Control](../administration/users.md#list-of-capabilities)).

1. In a list of entities, select 2 to 4 entities of the same type with the checkboxes at the start of the lines.
2. In the toolbar, click the **Merge** icon. The **Merge entities** panel opens.
3. In **Selected entities**, choose the main entity with the radio button at the end of its line. By default, the first selected entity is the main entity.
4. Check the preview in **Merged entity** (name, aliases, author and markings), then click **Merge**.
5. In the **Launch a background task** dialog, click **Launch**.

The merge runs as a [background task](background-tasks.md#knowledge-tasks): follow its progress in Data > Processing > Tasks. A merge cannot be undone.

## Preserving entity relationships

One of the key feature of the merge capability is its ability to preserve relationships. While merging entities, their interconnected relationships are not lost. Instead, they seamlessly integrate into the new, merged entity. This ensures that the intricate web of relationships within the data remains intact, fostering a comprehensive understanding of the threat landscape.


## Conclusion

OpenCTI’s merge capability helps improve the quality of threat intelligence data. By consolidating entities and centralizing relationships, OpenCTI empowers analysts to focus on insights and strategies, unburdened by data silos or fragmentation. However, exercising caution and foresight in the merging process is essential, ensuring a robust and streamlined knowledge basis.


## Additional resources

- **Administration:** To understand how to merge entities and the consideration to take into account, refer to the [Merging](../administration/merging.md) page in the Administration section of the documentation.
- **Deduplication mechanism:** the platform is equipped with [deduplication processes](deduplication.md) that automatically merge data at creation (either manually or by importing data from different sources) if it meets certain conditions.