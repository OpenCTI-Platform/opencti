# Curation

**Data > Curation** is the data-quality home of your knowledge base. Instead of separate menu entries, the work that keeps the knowledge clean lives in one place, as tabs. The tabs available today come from [provenance](provenance.md):

| Tab | What you do there |
| --- | --- |
| Conflicts | See the attributes your sources disagree on, and which value each source asserts ([details](provenance.md#curation-tabs)). |
| Stale knowledge | Find knowledge whose sources stopped confirming it, according to the knowledge decay rules ([details](provenance.md#curation-tabs)). |

Other data-quality pages join the hub as new tabs when they become available, without a new menu entry.

![The Data menu expanded with its Curation entry, and the Conflicts tab open under the breadcrumb Data > Curation > Conflicts, with the counters by kind of knowledge](assets/curation-hub-conflicts-open.png)

??? example "The same page in the light theme"

    ![The Data menu expanded on Curation in the light theme, with the Conflicts tab open](assets/curation-hub-conflicts-open-light.png)

## When the entry is shown

- **Curation** appears in the **Data** menu, right after **Relationships**, as soon as one of its tabs is available on your platform.
- Each tab has its own permission check: a tab you are not allowed to use is not listed, and the hub opens the first tab you can use.
- Each tab keeps its own address under `Data > Curation`, so a link to a tab can be bookmarked and shared.

## Working in the hub

- The breadcrumb `Data > Curation > <tab>` and the tab bar stay on screen while a tab loads, so switching tabs never blanks the page.
- A number next to a tab counts the work waiting for you there: the elements with source conflicts on **Conflicts**, the stale elements on **Stale knowledge**, the proposals to review in the Inbox. The **Curation** entry of the menu shows the sum of these numbers. They are never totals, and they disappear when nothing is waiting.
- A tab that has nothing to show yet says what it does and what feeds it, and offers its first action and a link to its documentation.
- Opening a link to Curation when none of its tabs is available to you shows a page that says so, with a way back to **Data**. The tabs may be hidden on your platform or need a permission your account does not have: ask your administrator if you need them.

## Related pages

- [Provenance](provenance.md): the sources, conflicts and freshness behind the Conflicts and Stale knowledge tabs.
- [Deduplication](deduplication.md): how OpenCTI avoids creating the same object twice.
- [Merge objects](merging.md): merging objects by hand.
- [Data consistency](dataSanityManager.md): consistency checks run by the platform.
