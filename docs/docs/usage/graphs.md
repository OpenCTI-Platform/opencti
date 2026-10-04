# Work with graphs

OpenCTI draws knowledge as graphs in several places: the **Graph** and **Correlation** views of containers (reports, groupings, incident responses, requests for information and for takedown), **investigations**, the graph view of the **Analyses** tab of an entity, and the explanation of an **inferred relationship**. All of them share the same graph, described on this page.

## Why use the graph?

A graph shows what a list cannot: who is connected to what, through which relationships, and how strongly. The graph is built to answer those questions quickly:

- every node says what it is (icon and colour of its type), what it carries (markings, a low confidence, an inference) and how certain its relationships are;
- focusing on an entity fades everything else, so its neighbourhood reads at a glance;
- deterministic layouts arrange the same graph the same way every time, from the threat to its victims;
- every element can be acted on from where it is drawn.

![Knowledge graph of a report, laid out by entity tier](assets/graph-knowledge-tiers.png)

## Where graphs appear

The same graph, with the same controls, is drawn on every surface below, in the dark and the light themes.

=== "Knowledge of a container"

    The **Graph** view of the **Knowledge** tab of a report, a grouping, a case or any other container draws its entities and relationships.

    === "Dark theme"

        ![Knowledge graph of a report on the Copper Lantern intrusion set, in the dark theme](assets/graph-knowledge.png)

    === "Light theme"

        ![Knowledge graph of a report on the Copper Lantern intrusion set, in the light theme](assets/graph-knowledge-light.png)

=== "Correlation"

    The **Correlation** view of a container links its observables and indicators to the other containers that share them.

    === "Dark theme"

        ![Correlation graph linking an IP address and a domain name to three reports, in the dark theme](assets/graph-correlation.png)

    === "Light theme"

        ![Correlation graph linking an IP address and a domain name to three reports, in the light theme](assets/graph-correlation-light.png)

=== "Investigation"

    An investigation of the **Investigations** workspace starts from a few entities and grows as you expand them (see [Pivot and investigate](pivoting.md)).

    === "Dark theme"

        ![Investigation of the Copper Lantern infrastructure, in the dark theme](assets/graph-investigation.png)

    === "Light theme"

        ![Investigation of the Copper Lantern infrastructure, in the light theme](assets/graph-investigation-light.png)

=== "Analyses of an entity"

    The graph view of the **Analyses** tab of an entity draws the containers in which the entity appears, with the other objects they share.

    === "Dark theme"

        ![Graph view of the analyses of the Copper Lantern intrusion set, in the dark theme](assets/graph-analyses.png)

    === "Light theme"

        ![Graph view of the analyses of the Copper Lantern intrusion set, in the light theme](assets/graph-analyses-light.png)

## Read the graph

### Nodes

Each entity is a disc tinted with the colour of its type, ringed with that colour and marked with the icon of its type, the same icon as everywhere else in the platform. Its name is written below; long names are shortened, the full name is in the hover card. Relationships that are themselves the source or target of another relationship are drawn as smaller nodes.

Above a node, **badges** give its state. At most three are drawn, the most severe first (an error before a warning), followed by `+2` for example when the entity carries more; the hover card lists every badge with what it means.

| Badge | Meaning |
|---|---|
| Coloured dot | The markings of the entity, in the colour of its first marking (for example TLP:GREEN), with their number when there are several; the hover card names each of them. |
| Gauge with a number | A low confidence (below 50), with its value. |
| Wand | The entity is inferred by the rules engine. |
| Clock, warning colour | Stale knowledge: no source asserted the entity for longer than the decay rules allow (see [Provenance](provenance.md)). |
| Split arrow, error colour | The sources of the entity disagree on some of its values. |

Knowledge asserted by several distinct sources is circled by a second, success-coloured ring outside the ring of its type, thicker with every additional source; the hover card gives the number of sources.

Other features of the platform can add their own badges (see [Extend the graph](#extend-the-graph)).

An entity you do not have access to, because of its markings or of an organization restriction, is drawn with a dashed outline and named **Restricted**; its hover card says that you do not have access to it.

In investigations, a small counter on the top right of a node tells how many relationships of the entity are not drawn yet (`5+`, `99+`, or `?` while the count loads).

### Links

| Style | Meaning |
|---|---|
| Plain line | A relationship asserted in the knowledge base. |
| Dashed line, warning colour | An inferred relationship. |
| Dotted line | A relationship with a low confidence (below 50). |

Links end with an arrowhead on their target. Several relationships between the same two entities are fanned out instead of drawn on top of each other. The name of a relationship appears along its link when you zoom in, or when the link is selected or hovered, followed by the number of its sources when several sources assert it (for example `uses (3)`). A label never covers an entity: it slides along its link when the middle is taken, and is left out when it finds no free place.

In the deterministic layouts, which line entities up, a link that would run through another entity bends around it, so that it never reads as two links.

### Level of detail

Details appear as they become readable: far out, nodes are plain discs; closer, icons, names, badges, arrowheads and relationship names appear. The entity hovered, selected or on a highlighted path always keeps a readable name.

## Navigate

The controls on the top left of the graph zoom in and out, fit the whole graph, fit the selection, centre the view on the selection, show or hide the legend, show the graph full screen and export it. Fitting keeps every entity clear of the controls, the counters, the legend and the details panel. A graph opened for the first time is fitted again once its layout settles, unless you zoomed or moved it meanwhile; afterwards it opens as you left it. In full screen, the toolbar and every dialog stay available; press `Esc` or the control again to leave.

Next to the controls, the **counter row** sums up the graph: the number of entities (members of collapsed groups included) and of relationships drawn, the entities you do not have access to (**restricted**) and the entities that **need attention** because they carry a warning or an error badge, such as a low confidence or stale knowledge. Click a counter to select what it counts, then fit the selection, open it or act on it from the toolbar.

## Focus and hover cards

Hovering an entity or a relationship, or selecting it, keeps it and its direct neighbours at full strength and fades the rest of the graph.

After a short moment on an element, a **hover card** opens with its key facts: type, name, date, author, confidence, number of sources, markings, relationship counts, every badge with what it means and, in investigations, the number of relationships not drawn yet. Its quick actions apply to the entity directly:

- **Open in a new tab**;
- **Expand this entity** (investigations);
- **Pin at its place** / **Unpin**;
- **Hide from the view** (the entity is not removed from the container or the investigation; the legend shows it back);
- **Select with its neighbours**;
- **Lay out the graph around it** (radial layout);
- **Shortest path from the selection** and **Create a relationship from the selection**, when one other entity is selected;
- **Start an investigation** (outside investigations, for users allowed to create them, not in a draft): a new investigation opens with the entity, or with every selected entity when the entity is part of the selection.

![Hover card of the Copper Lantern intrusion set, with its facts, markings, relationship counts and quick actions](assets/graph-hover-card.png)

## The legend

The legend on the bottom left counts the entities of each type and the relationships of each type drawn in the graph.

- Click a counter to fade or restore every entity or relationship of that type, like the type filters of the toolbar.
- Use the button next to an entity type to **collapse** all its entities into a single group node, and again to expand it. A click on a group node expands it too. Relationships towards the members of a group are drawn once towards the group.
- When entities are hidden, **Show the hidden entities** brings them back.
- The **Badges** section lists only the badges present in the graph, with the number of entities carrying each; click one to select those entities.

When the time range selector of the toolbar is open, the legend moves up so that the whole slider stays free.

## Layouts

The toolbar at the bottom offers several layouts. All of them except the forces are deterministic: the same graph is always drawn the same way, and nodes glide to their new place.

| Layout | Use it to |
|---|---|
| Forces (default) | Let related entities gather; drag nodes to arrange them, their positions are saved. |
| Vertical / horizontal tree | Follow the direction of the relationships, from sources to targets, top to bottom or left to right. Cycles are handled. |
| Layout by entity tier | Read an attack left to right: threats, arsenal, techniques, observables and indicators, victims, locations, then containers. |
| Radial layout | Put one entity at the centre (the selected one, or the most connected) and the others on rings by distance. |

**Unfix the nodes and re-apply forces** forgets the saved positions and lets the forces arrange the graph again.

![Investigation graph in the horizontal tree layout](assets/graph-investigation-tree.png)

## Select

Besides clicking (with `Ctrl`, `Shift` or `Alt` to add to the selection), the toolbar selects with a rectangle or a free shape, by entity type, all nodes, or the relationships of the selected nodes. It also:

- **selects the neighbours** of the selected nodes;
- **highlights the shortest path** between two selected nodes, whatever the direction of the relationships; the path stays highlighted until the selection changes.

The search field of the toolbar selects the matching entities.

![Focus on a selected entity and its neighbours](assets/graph-focus.png)

## Keyboard shortcuts

Shortcuts apply while the pointer is over the graph or the focus is inside it, never while typing in a field or when a dialog is open. Press `?` to list them in the platform.

| Keys | Action |
|---|---|
| `F` / `Shift` + `F` | Fit the whole graph / fit the selection |
| `L` | Locate the selection |
| `+` / `-` | Zoom in / zoom out |
| `Ctrl` + `A` | Select all nodes |
| `N` | Select the neighbours of the selection |
| `P` | Highlight the shortest path between the two selected nodes |
| `H` / `Shift` + `H` | Hide the selection / show the hidden entities |
| `Esc` | Clear the selection (leave full screen when nothing is selected) |
| `G` | Show or hide the legend |
| `Shift` + `M` | Full screen |
| `Shift` + `E` | Export the whole graph as a high-resolution image |
| `/` | Search in the graph |

## Export

Two exports are available:

- the **image export** of the container or workspace header captures the visible area of the page, in PNG or PDF;
- the **Export the whole graph as a high-resolution image** control renders the whole graph, not only the visible area, at print resolution, with a title and a legend of the entity types and line styles.

## 3D mode

The 3D mode shows the same graph in three dimensions, with the same filters, hidden entities, groups and selection. Selection shapes, the legend and the deterministic layouts other than the trees are available in 2D only.

## Accessibility

Every entity and relationship drawn is mirrored in a list box that keyboard and screen reader users can reach with `Tab`: the arrow keys move in the list, `Enter` or `Space` selects the element (with `Shift` to add it to the selection), and the keyboard shortcuts above apply.

## Extend the graph

Features of the platform add states and actions to the graph without changing it:

- a **badge provider** returns badges for a node from the data the graph received, and returns nothing when its data is absent;
- a **node action** adds a quick action to the hover card of the nodes it applies to.

Both are registered in `opencti-platform/opencti-front/src/components/graph/badges/` (see `graphBadgeRegistry.ts` and `graphNodeActionRegistry.ts`); the stale knowledge and source conflict badges of the provenance feature are an example.

## What's next?

- [Pivot and investigate](pivoting.md) with the investigation graph.
- [Analyses](exploring-analysis.md): the graph and correlation views of containers.
- [Inferences](inferences.md) and the graph explaining an inferred relationship.
