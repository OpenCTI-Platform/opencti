# Time series breakdown

A time series widget can be broken down by the values of a field: instead of one series per dataset, OpenCTI draws one series per value of the field you pick, such as one series per label, per analyst or per author. The values are found in the data each time the widget is displayed, so you never list them by hand.

A typical use is to follow the reports handled by each analyst, week by week, without knowing the analysts in advance.

![Dashboard with broken down widgets](assets/time-series-breakdown-01-dashboard.jpg)

A dashboard with four broken down widgets: reports per week by label, per week by assignee, per month by author, and per week by report type.

## Why use it?

Without a breakdown, comparing values means adding one dataset per value, as described in [Tips for widget creation](tips-widget-creation.md#use-case-2-break-down-your-chart). This is limited to 5 datasets, and every new value (a new analyst, a new label) needs a new dataset.

With a breakdown:

- **One dataset is enough.** Its filters and its date attribute apply to every series.
- **Values are discovered automatically.** The widget stores the field, never the list of values: a new analyst shows up in the widget without any change.
- **Up to 50 series.** You choose how many, and whether to keep the highest or the lowest values.
- **The rest is not lost.** An optional **Other** series groups everything that is not displayed.

## Where you can use it

| Applies to | Supported |
|---|---|
| **Visualizations** | Vertical bars, Line, Area and Heatmap |
| **Perspectives** | Entities, Knowledge graph (relationships), Activity & history (audits, Enterprise Edition) |
| **Containers** | [Custom dashboards](dashboards.md), [custom views](custom-views.md) and [public dashboards](dashboards-share.md) |

Breakdowns are not available in Fintel templates, nor on widgets that count drafts. On the Activity & history perspective, a Line or an Area that counts distinct values cannot be broken down: a breakdown counts every event.

## Break down a widget

1. In a custom dashboard, click **Create Widget**, or edit an existing widget.
2. **Visualization**: choose Vertical bars, Line, Area or Heatmap.
3. **Perspective**: choose the perspective of the data to count.
4. **Filters**: define a single dataset, for example *Entity type = Report*, then click **Validate filters**. A message reminds you that this dataset can be broken down at the next step.
5. **Parameters**: choose the field in **Break down by**, then set the other breakdown options (see below).
6. Click **Create** (or **Update**).

![Filters step](assets/time-series-breakdown-03-dataset-step.jpg)

At the **Filters** step, the message *You can break this dataset down into one series per field value in the Parameters step.* is shown as long as the widget has a single dataset.

![Parameters step](assets/time-series-breakdown-04-parameters-step.jpg)

The breakdown options are in the **Parameters** step, next to the interval:

| Option | Description |
|---|---|
| **Break down by** | The field whose values become the series. **None** keeps a regular widget. |
| **Maximum number of series** | 5, 10, 20 or 50. Default: 10. |
| **Order** | **Highest values** keeps the values that count the most over the whole period, **Lowest values** the ones that count the least. |
| **Include Other** | Adds an **Other** series that groups everything outside the displayed values, including the data without any value for the field. |

!!! note "A breakdown uses a single dataset"

    While a breakdown is set, you cannot add a second dataset to the widget: the button that adds one is disabled, with the tooltip *A breakdown uses a single dataset.* If the widget already has several datasets, **Break down by** is disabled with the same tooltip, and the other breakdown options are hidden. Remove the extra datasets to break the widget down.

![Breakdown options disabled with two datasets](assets/time-series-breakdown-06-two-datasets.jpg)

### Fields you can break down by

The fields offered depend on the perspective and on the types the dataset filters on. With a single entity type, you get the fields of that type (for example *Report types* for reports). With several types, you get the fields they share, plus *Entity type*.

![Fields offered for reports](assets/time-series-breakdown-05-break-down-by-options.jpg)

| Perspective | Fields |
|---|---|
| **Entities** | Author, Creators, Label, Markings, Assignees, Participants, the vocabulary and list fields of the entity type (for reports: *Report types*), and *Entity type* when the dataset has several types |
| **Knowledge graph** | Relationship type, Source type, Target type, and the fields the relationship types carry (Author, Creators, Label, Markings...) |
| **Activity & history** | Event type, Event scope, User, Group, Organization, Type, Type of related entity |

For example, a dataset on reports offers *Assignees*, *Author*, *Creators*, *Label*, *Markings*, *Participants* and *Report types*.

Some fields are never offered: the fields pointing to other knowledge entities (*Contains*, *External references*, *Kill chain phases*), free text fields and dates. The server refuses them too.

## How the series are computed

OpenCTI computes the whole breakdown on the server, in a single query, whatever the number of series. It only counts the data you are allowed to see: your markings and organizations apply.

```mermaid
flowchart LR
  D["<b>Dataset</b><br/>filters, date attribute,<br/>period"] --> R["<b>Rank the values</b><br/>of the field<br/>over the whole period"]
  R --> N["<b>Top N</b><br/>highest or lowest"]
  N --> S["<b>One series</b><br/>per value"]
  R --> O["<b>Other</b> (optional)<br/>the remaining values<br/>and the data without value"]
```

Keep in mind the following behaviors when you read a broken down widget:

| Case | Behavior |
|---|---|
| **Multi-valued fields** (labels, assignees, markings...) | An entity counts in every series of its values: a report with two labels counts twice. The sum of the series is not a number of entities. |
| **Data without a value** (unassigned, unlabeled) | It is not in any series, but it is counted in **Other** when **Include Other** is on. |
| **Current value of the field** | The breakdown uses the current value of the field, placed at the date of the dataset. Reassigning a report moves it to its new assignee for the whole period. |
| **Top N** | The highest or lowest values are ranked over the whole period, so the series stay the same from the start to the end of the chart. |
| **Filter on the broken down field** | A filter narrows the data, not the series: with *Label = ransomware*, the other labels of these reports show up too. |
| **Values you cannot access** | They are shown as *Restricted*. When several series share a name, they are numbered. |
| **Values that cannot be resolved** (a deleted user) | They are ignored, without taking a place in the top N. |
| **Date attribute** | The series use the date attribute of the dataset. The default technical date groups imported data at its import date: prefer a business date (publication date, creation date) for reports. |

### Colors

Each value keeps the same color in every widget: a label keeps its color, a marking its color, and an entity type the color the platform gives it. The other values get a color derived from the value itself, and no two series of a widget share one. **Other** is always grey.

### Default period

Without a start date on the dashboard, a daily breakdown covers the 30 days before the end date (today when there is no end date). A period set on the dashboard is always respected.

## Warnings and limits

A broken down widget can hold many series and many points. OpenCTI warns you instead of drawing a misleading chart.

![Top values warning](assets/time-series-breakdown-07-top-n-warning.jpg)

| Situation | What the widget shows |
|---|---|
| More values than the maximum number of series | A warning icon next to the title: *Only the 5 highest values are displayed.* (or *lowest*) |
| Too many bars, points or cells for the width of the widget | The chart counts by a coarser interval (days, then weeks, months...) and the warning icon says *Interval adjusted to Week to keep the chart responsive.* When weeks are summed into months, each week is counted in the month that contains its Monday. |
| More than 5,000 distinct values with **Lowest values** | *There are too many values to find the lowest ones.* Choose the highest values or narrow the filters. |
| More than about 50,000 points (series × intervals), for example 50 daily series over 3 years | *This breakdown has too many points for the selected period.* Shorten the period, choose a coarser interval or reduce the number of series. |
| A field or a date attribute that does not apply to the data of the widget | *This breakdown field is not available for the dataset of this widget.* or *The date attribute of this widget does not apply to its data.* |

![Interval adjusted](assets/time-series-breakdown-08-interval-adjusted.jpg)

When a breakdown cannot be computed, the widget shows the reason in place of the chart. Users who can edit the widget also get the advice on what to change.

![Breakdown refused](assets/time-series-breakdown-12-refusal.jpg)

A widget breaking reports down by 50 labels, day by day since 2023: the breakdown has too many points, and the widget says how to fix it.

!!! tip "Keep breakdowns readable"

    Beyond 15 to 20 series, a chart gets hard to read. Prefer 5 or 10 series with **Include Other**, a weekly or monthly interval over long periods, and a heatmap when you want to compare many values.

## Examples

### Reports per analyst

The original use case: count the reports of each analyst, week by week. Choose a Heatmap, the Entities perspective, a dataset on Reports, then **Break down by** *Assignees* with a **Week** interval.

![Reports per analyst](assets/time-series-breakdown-02-use-case-heatmap.jpg)

### Relationships by type

On the Knowledge graph perspective, break down relationships by *Relationship type* to see which kinds of knowledge grow over time.

![Relationships by type](assets/time-series-breakdown-09-relationships.jpg)

### Platform activity by user

On the Activity & history perspective, break down the events by *User* or by *Event type* to follow the activity on the platform. A Vertical bars widget counts every event; a Line or an Area that counts distinct values cannot be broken down.

!!! tip "Enterprise edition"

    Widgets of the Activity & history perspective, broken down or not, are available in the **OpenCTI Enterprise Edition**. Please read the [dedicated page](../administration/enterprise.md) for full details.

## Public dashboards

A broken down widget is published as is: the [public dashboard](dashboards-share.md) shows the same series, colors, legend and warnings as the custom dashboard.

![Public dashboard](assets/time-series-breakdown-11-public-dashboard.jpg)

- The breakdown settings are read from the widget stored in the dashboard, never from the visitor's request.
- The data follows the restrictions of the public dashboard: the access of its creator, limited to the markings chosen at publication.
- Visitors can pick any period: a long period is counted in coarser intervals, so that the widget draws at most 5,000 points, and the widget says so.
- Widgets of the Activity & history perspective are not available in public dashboards, broken down or not.

## Export, import and visualization changes

- A broken down widget is exported and imported with its breakdown. Imported into an older version of OpenCTI, it loses its breakdown without any error and shows a single total series.
- Switching the widget to a visualization that cannot be broken down (a donut, a list...) removes the breakdown when you save the widget.

## Related pages

- [Widget creation](widgets.md): the four steps of the widget editor.
- [Tips for widget creation](tips-widget-creation.md): choosing a visualization and adding datasets.
- [Custom views](custom-views.md) and [public dashboards](dashboards-share.md): the other places where broken down widgets are displayed.
