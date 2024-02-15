# Filter knowledge

In OpenCTI, you can filter data to target or view entities that have particular attributes.

## Filters usages

Filters are used in many locations in the platform.

* in entities lists: to display only the entities matching the filters. If an export or a background task is generated, only the filtered data will be taken into account.
* in investigations and knowledge graphs: to display only the entities matching the filters.
* in dashboards: to create Widget graphs and lists with only the entities matching the filters.
* in feeds, taxii collections, triggers, streams, playbooks, background tasks: to process only the data  or events matching the filters.

There are two types of filters:

* **dynamic filters**: they are not stored in the database, they enable to filter view in the UI. Examples: filters in entities list, investigations, knowledge graphs;
* **stored filters**: They are attributes of an entity, they are stored as an attribute in the object. Examples: filters in dashboards, feeds, taxii collections, triggers, streams, playbooks.

![Filtering entities](./assets/filters-migration-example1.png)

## Create a filter

To create a filter, add every key you need using the 'Add filter' select box. It will give you the possible attributes on which you can filter in the current view.

A grey box appears and allows to select:

* the operator to use
* the values to compare (if operator is not 'empty' or 'not_empty')

You can add as many filters as you like, even use the same key twice with different operators and values.

The boolean modes (and /or) are either **global** (between every attribute filters) or **local** (between values inside a filter).
Both can be switched with a single click, changing the logic of your filtering.

## Dynamic filters persistence

Dynamic filters are not saved in database, but they are still persistent in the platform frontend side.
The filters used in a view are saved as URL parameters, so you can save and share links of these filtered views.

Also, your web browser saves in local storage the filters that you are setting in various places of the platform, allowing to retrieve them when you come back to the same view.
You can then keep working from where you left of.

## Filters format (since 5.12)

Since OpenCTI 5.12, the OpenCTI platform uses a new filter format called `FilterGroup`, that must be used in API calls.
The `FilterGroup` model enables to do complex filters imbrication with different boolean operators, which extends greatly the filtering capabilities in every parts of the platform.

The new format used internally by OpenCTI and exposed through its API, can be described as below:

```ts
// filter formats in OpenCTI >= 5.12

type FilterGroup = {
  mode: 'and' | 'or'
  filters: Filter[]
  filterGroups: FilterGroup[] // recursive definition
}

type Filter  = {
  key: string[] // or single string (input coercion)
  values: string[]
  operator: 'eq' | 'not_eq' | 'gt' // ... and more
  mode: 'and' | 'or',
}

// "give me Reports and RFIs, not marked TLP;RED, with no label or labelX"
const filters = {
  mode: 'and',
  filters: [
    { key: 'entity_type', values: ['Report', 'Case-Rfi'], operator: 'eq', mode: 'or', },
    { key: 'objectMarking', values: ['<id-for-TLP;RED>'], operator: 'not_eq', mode: 'or', },
  ],
  filterGroups: [{
    mode: 'or',
    filters: [
      { key: 'objectLabel', values: ["<id-for-labelX>"], operator: 'eq', mode: 'or', },
      { key: 'objectLabel', values: [], operator: 'nil', mode: 'or', },
    ],
    filterGroups: [],
  }],
};
```

We can express complex, nested filters like:

```
(Entity Type = Malware) AND (Marking = TLP;CLEAR or TLP;GREEN)
OR
(Entity Type = Intrusion Set) AND (Label = labelX)  
```

In a given filter group, the `mode` (`and` or `or`) represents the boolean operation between the different `filters` and `filterGroups` arrays.
The `filters` and `filterGroups` arrays are composed of objects of type Filter and FilterGroup.

The `Filter` has 4 properties:

* a `key`, representing the kind of data we want to target (example: `objectLabel` to filter on labels or `createdBy` to filter on the author)
* an array of `values`, representing the values we want to compare to
* an `operator` representing the operation we want to apply between the `key` and the `values`
* a `mode` (again, `and` or `or`) to apply between the values if there are several ones

### Operators
The available operators are:

* `eq`  for 'equal', and `not_eq` for 'different',
* `gt` / `gte` for 'greater than' / 'greater than or equal',
* `lt` / `lte` for 'lower than' / 'lower than or equal',
* `nil` for 'empty', and `not_nil` for non-empty (any value),
  * Note that `nil` and `not_nil` are the only operators that do not require anything inside `values`.
* `starts_with` / `not_starts_with` / `ends_with` / `not_ends_with` / `contains` / `not contains` are available for searching in short string fields (name, value, title...).
* `search`  is available in short string and text fields.

When using a numerical comparison operators (`gt` and the like) against textual values, the alphabetical ordering is used.

Some operator may not be allowed for some key, for additional information please navigate to the "Special keys" section.

There is a small difference between `search` and `contains`. `search` finds any occurrence of specified words, regardless of order, while "contains" specifically looks for the exact sequence of words you provide.

Also note that GraphQL input coercion makes possible using a simple `string` key instead of an array.
Multi-key filters are not supported across the platform and are reserved to specific, internal cases.
**Bottom line: Always use single-key filters.**


### Examples of filter using OpenCTI version 5.12+

* entity_type = 'Report'

```
filters = {
    mode: 'and',
    filters: [{
        key: 'entity_type',
        values: ['Report'],
        operator: 'eq',
        mode: 'or', // useless here because values contains only 1 value
    }],
    filterGroups: [],
};
```

* (entity_type = 'Report') AND (label = 'label1' OR 'label2')

```
filters = {
    mode: 'and',
    filters: [
        {
            key: 'entity_type',
            values: ['Report'],
            operator: 'eq',
            mode: 'or',
        },
        {
            key: 'objectLabel',
            values: ['label1', 'label2'],
            operator: 'eq',
            mode: 'or',
        }
    ],
    filterGroups: [],
};
```

* (entity_type = 'Report') AND (confidence > 50 OR marking is empty)

```
filters = {
    mode: 'and',
    filters: [
        {
            key: 'entity_type',
            values: ['Report'],
            operator: 'eq',
            mode: 'or',
        }
    ],
    filterGroups: [
        {
            mode: 'or',
            filters: [
                {
                    key: 'confidence',
                    values: ['50'],
                    operator: 'gt',
                    mode: 'or',
                },
                {
                    key: 'objectMarking',
                    values: [],
                    operator: 'nil',
                    mode: 'or',
                },
            ],
            filterGroups: [],
        }
    ],
};
```

### Filter keys

#### Filter keys validation

Only a specific set of key can be used in the filters.

Automatic key checking prevents typing error when constructing filters via the API:
if a user write an unhandled key (`object-label` instead of `objectLabel` for instance), the API will return an error instead of an empty list.
Doing so, we make sure the platform do not provide misleading results.

#### Regular filter keys
For an extensive list of available filter keys, refer to the attributes and relations schema definitions.

Here are some of the most useful keys as example.
X refers here to the filtered entities.

* ``objectLabel``: label of X,
* ``objectMarking``: marking of X,
* ``createdBy``: author of X,
* ``creator_id``: technical creator of X,
* ``created_at``: date of creation of X in the platform,
* ``confidence``: confidence of X,
* ``entity_type``: X entity type ('Report', 'Stix-Cyber-Observable', ...),

#### Special filter keys
Some keys do not exist in the schema definition, but are allowed in addition. They describe a special behavior.

It is the case for:

* ``sightedBy``: entities to which X is linked via a stix sighting relationship,
* ``elementId``: entities to which X is related via a stix core relationship,
* ``connectedToId``: the listened instances for an instance trigger.

For some keys, negative equality filtering is not supported yet (`not_eq` operator). For instance, it is the case for:

* ``fromId``
* ``fromTypes``
* ``toId``
* ``toTypes``

#### Limited support in stream events filtering
Filters that are run against the event stream are not using the complete schema definition in terms of filtering keys.

This concerns:

* Live streams
* CSV feeds
* Taxii Collection
* Triggers
* Playbooks

For filters used in this context, only some keys are supported for the moment:

* ``confidence``
* ``objectAssignee``
* ``createdBy``
* ``creator``
* ``x_opencti_detection``
* ``indicator_types``
* ``objectLabel``
* ``x_opencti_main_observable_type``
* ``objectMarking``
* ``objects``
* ``pattern_type``
* ``priority``
* ``revoked``
* ``severity``
* ``x_opencti_score``
* ``entity_type``
* ``x_opencti_workflow_id``
* ``connectedToId`` (for the instance triggers)
* ``fromId`` (the instance in the 'from' of a relationship)
* ``fromTypes`` (the entity type in the 'from' of a relationship)
* ``toId``
* ``toTypes``
