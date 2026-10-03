# Graph analytics: paths, similarity and clusters

OpenCTI computes deterministic analytics on top of your knowledge graph: how two entities are connected, which threats or infrastructures look alike, which elements form a cluster, and which entities are the hubs of your graph. Every result is explained by the knowledge it comes from, and none of them is ever written as a relationship: turning an analytics result into knowledge is always an explicit analyst action.

Graph analytics are part of the Community Edition and do not use any AI.

## Why use graph analytics?

- **Answer "how is this connected?" in one click**: find how an IP address relates to an intrusion set, or how two campaigns share infrastructure, instead of expanding the graph manually.
- **Spot look-alikes**: list the intrusion sets, malware or infrastructures that share the most techniques, tools, victims, certificates or hosting with the one you are looking at, with the shared elements as evidence.
- **Group what belongs together**: surface clusters of infrastructure sharing certificates, ASNs, registrars or name servers, and turn them into a Grouping or a Campaign when you agree.
- **Prioritize**: sort and filter any list or widget by the number of connections of an entity (graph degree), its approximate betweenness (how often it bridges parts of the graph) or the size of its cluster.

!!! note "Access rights"

    Analytics respect markings and organization restrictions. A path never goes through an entity you cannot access, a similar entity is only listed when you can access it, and only the shared evidence you can access is displayed.

## Find paths between two entities

### From an entity

1. Open any entity and click the **Connect to...** button in the header.
2. Select the target entity.
3. Optionally adjust the search: maximum path length (4 relationships by default, 6 at most), number of paths, relationship types and intermediate entity types, inferred relationships, or going through containers (reports, groupings, cases).
4. Click **Find paths**. The shortest paths are listed first, each one as a chain of entities and relationship types. Longer paths are only listed when they reach each of their entities by its shortest route: a detour through an entity already reached by a shorter path is not listed.
5. Select the paths you are interested in and click **Start an investigation with the selected paths** to open them in a new investigation.

The search is bounded in time and in explored entities. When a limit is reached, a warning tells you that longer paths may exist: narrow the search with relationship or entity types.

### In an investigation

Select two entities in the investigation graph and click **Find path** in the toolbar. The selected paths are added to the graph, and the rollback button removes them like any other expansion.

## Similar entities

### The Similar tab

Threats (intrusion sets, threat actors, campaigns), malware, infrastructures, domain names, hostnames, IP addresses, URLs, certificates and reports have a **Similar** tab listing their look-alikes. For each similar entity, the tab shows:

- the **similarity score**, combining a weighted Jaccard index of the shared elements and a structural similarity of the relationship types,
- the **shared evidence**, grouped by family, each element being a link to the entity,
- a flag when an existing **OpenAEV scenario** covers the similar threat (through its Security Coverage), with a filter to only list those,
- actions to **compare side by side** or open the entity in a new tab.

The **Investigate these similar entities** button starts an investigation with the entity, its look-alikes and the shared evidence.

### How similarity is computed

Entities are only compared with entities of the same kind, on the elements that characterize them:

| Entity types | Shared elements used |
|---|---|
| Intrusion sets, threat actors, campaigns, malware | Techniques, tools and malware they use, infrastructures they use or control, victims they target (sectors, organizations, individuals, locations) |
| Infrastructures and observables | Certificates, autonomous systems, registrars, name servers, co-hosted names or addresses, related infrastructures and malware, reports they appear in |
| Reports | Objects they contain |

Rare and specific elements (certificates, malware, infrastructures, name servers) weigh more than broad context (victims, autonomous systems). Elements shared by too many entities, such as a popular hosting provider, are not used to find look-alikes, so that a common element alone does not make two entities similar. A score is never displayed without at least one shared element.

Similarities are computed in the background by the [graph analytics manager](../deployment/advanced/managers.md#graph-analytics-manager) about a minute after the knowledge of an entity changes, and refreshed every night. Click **Refresh similarity** in the Similar tab to request an immediate recompute.

### In an investigation

- **Expand by similarity**: select entities in the investigation graph to list their look-alikes, then add the ones you choose to the graph.
- **Similarity matrix**: select up to 25 entities to compare them pairwise in a heat map.

## Clusters

The **Analyses > Graph clusters** page lists clusters of entities that belong together:

| Kind | Content |
|---|---|
| Infrastructure cluster | Mostly infrastructures and observables (IP addresses, domain names, URLs, certificates, autonomous systems) sharing certificates, autonomous systems, registrars, name servers, hosting or report co-occurrences |
| Tooling cluster | Mostly malware, tools and attack patterns used together |
| Campaign cluster | Other communities of the graph, typically threats, campaigns, their victims and the reports they appear in |

The platform computes infrastructure clusters from shared features. On large platforms, the optional analytics process detects communities in the whole graph and computes the three kinds.

The page shows who computes the clusters (the platform, or the optional analytics process on large platforms), when the knowledge was last analyzed, and the growth of the largest clusters.

The detail of a cluster shows its members (most connected first), its shared features, its representative entities and the growth of its membership. From there:

- **Create Grouping** creates a Grouping containing the members you can access, and optionally the shared features.
- **Create Campaign** creates a Campaign related to the members you can access.
- **Add to investigation** opens the members and shared features in a new investigation.

A Grouping or a Campaign always holds every member you can access: a cluster with more than 2,000 accessible members cannot be promoted, and the cluster page says so.

A cluster keeps its identity from one computation to the next, so the Groupings and Campaigns it was promoted to remain listed on it.

## Graph metrics on entities

Every entity carries graph metrics, refreshed in the background without changing its modification date:

- **Graph degree**: number of relationships and sightings of the entity.
- **Approximate betweenness**: how often the entity lies on the shortest paths between other entities (computed by the analytics process).
- **Graph cluster** and **graph cluster size**: the cluster the entity belongs to.

You can filter on **Graph degree** and **Graph cluster** in lists and dashboards, sort lists by these metrics, and display them as list widget columns. For instance, a list widget of intrusion sets sorted by graph degree shows the hubs of your threat landscape.

## Dashboards

Two widgets are dedicated to graph analytics (see [widget creation](widgets.md)):

- **Similarity matrix**: pairwise similarity of the most connected entities of the selection, up to 25 entities.
- **Cluster size over time**: growth of the largest clusters whose members match the selection, up to 20 clusters.

Both are available in public dashboards.

## What's next?

- [Pivot and investigate](pivoting.md) in investigations.
- [Deploy and configure graph analytics](../deployment/graph-analytics.md), including the analytics process for large platforms.
