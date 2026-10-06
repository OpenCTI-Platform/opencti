# Graph badges and node actions

Every graph of the platform (container knowledge and correlation graphs, investigations, the graph
view of the Analyses tab) is drawn by the shared component `src/components/graph/`. A feature that
has a state to show on the nodes, or an action to offer from a node, plugs into it through two
registries instead of editing the graph:

- `badges/graphBadgeRegistry.ts`: badges drawn above the nodes (in the image export too), listed in
  the hover card, the legend and the accessible list; the legend of the image export lists the
  entity types and line styles only;
- `badges/graphNodeActionRegistry.ts`: quick actions of the node hover card.

Both are soft checks: a feature whose data is absent from a graph shows nothing there, and nothing
it registers can break the drawing.

## Badge provider contract

```ts
import { registerGraphBadgeProvider, type GraphBadgeProvider } from '@components/graph/badges/graphBadgeRegistry';

export const threatPulseGraphBadgeProvider: GraphBadgeProvider = {
  id: 'threat-pulse',  // unique; registering the same id again replaces the provider
  order: 50,           // among badges of the same tone, lower is drawn first; 0-99 are built in
  badgesFor: (node, { t_i18n }) => {
    const pulse = (node.raw as { pulse_trend?: string | null } | undefined)?.pulse_trend;
    if (pulse !== 'rising') return [];
    return [{
      key: 'threat-pulse-rising',             // stable: the legend groups the nodes by key
      icon: TrendingUpOutlined,               // an MUI or mdi icon, drawn on the canvas
      tone: 'warning',                        // neutral | info | success | warning | error | accent
      label: t_i18n('Rising threat'),         // hover card, accessible list, legend
      tooltip: t_i18n('Reported by more sources this week than the week before'),
    }];
  },
};
```

| Field | Rule |
|---|---|
| `id`, `order` | One provider per state family. Built-in providers (markings 10, confidence 20, inferred 30) come first. |
| `key` | Stable for the state, not for the node: the legend counts and selects the nodes by key. The registry prefixes it with the provider `id`, so it only has to be unique among the badges of your provider. |
| `tone` | By meaning, the same as the chips of the product: `success` done or positive, `info` in progress or informational, `warning` partial or needs attention, `error` failed or blocking, `neutral` not applicable. The colour comes from the theme; `color` is only for a colour carried by the data (a marking). |
| `label` | Translated, sentence case, no raw enum value or identifier. A label specific to the node (for example with a score) sets `legendLabel` to the generic name shown in the legend. |
| `tooltip` | Translated sentence saying what the badge means; the hover card and the legend show it. |
| `value` | Optional short text drawn in a pill next to the icon, for example a score. |

Rules the graph enforces, so a provider cannot get them wrong:

- **One badge per provider and node.** When a provider returns several, only the most severe is kept.
  Two independent states are two providers (as the markings and the confidence in `builtinGraphBadges.ts`).
- **At most three badges drawn per node**, the most severe first (error, warning, accent, info,
  success, neutral), then by provider order; the others are counted in a `+N` marker. Every badge
  stays listed in the hover card, so a failed or blocking state is never the one hidden.
- **Warning and error badges count as "need attention"** in the counter row above the canvas.
- A provider that throws is skipped for that node. A provider must still never throw, fetch or read
  anything but `node.raw` (the object received from the graph query): return `[]` when your fields
  are absent.

## Registering

1. Write the provider in a file of your feature, next to its other components (the built-in
   providers of `src/components/graph/badges/builtinGraphBadges.ts` are the reference, with their
   unit test in `graphBadgeRegistry.test.ts`).
2. Export a `registerXxxGraphBadges()` function and call it from `src/components/graph/badges/index.ts`
   (one import line, one call).
3. If the badge needs a field that the graph queries do not fetch, add it to the graph fragments
   (`GraphContainerKnowledge`, `GraphContainerCorrelation`, `InvestigationGraph`,
   `StixCoreObjectOrStixCoreRelationshipContainersGraph`) in the same pull request.
4. Add the label and the tooltip to every `lang/front/*.json` file, and a unit test that the provider
   returns `[]` without its fields and the expected badge with them.

## Node actions

`registerGraphNodeAction` adds a button to the node hover card with the same soft-check rule:
`isAvailable(node, context)` decides where it applies (`context` is the one given to `GraphProvider`:
`investigation`, `correlation`, `analyses`, or `undefined` for container knowledge graphs), and the
action is either an in-app `href` or an `onSelect` callback. Use it for actions that belong to a
feature, such as opening the Changes tab of an entity or planning a hunt from it; generic graph
actions (open, expand, pin, hide, layouts, paths) are built in.
