# Dashboard variables and presets

A custom dashboard can be *verticalized*: instead of maintaining one copy of the dashboard per client, per sector or per team, you define **variables** once, reference them in the filters of your widgets, and switch their values in one click. A **preset** saves a set of values, time range included, so a whole view of the dashboard is restored at once.

!!! note "Who can do what"

    Creating, editing and deleting variables and presets requires the *Create / update dashboards* capability and an edit right on the dashboard. Viewers only get the controls the dashboard editor opens for them (see [Viewer permissions](#viewer-permissions)).

## Variables

### Create a variable

On the page of a dashboard, the variables bar sits below the time filters. Click **Create variable** to open the creation dialog:

- **Name**: unique within the dashboard.
- **Type**: entity (restricted to one or several entity types), label, marking, user, group, status, kill chain phase, vocabulary (of a given category), entity type, text, number, boolean or date.
- **Restriction** (for the types that support it): *No restriction*, *Manual selection* (a closed list of values, up to 200) or, for entity variables, *By filter* (only the entities matching a filter can be picked).

A dashboard holds up to 50 variables; names are limited to 200 characters.
- **Default value**: mandatory. It is the value every user sees until they pick another one.

The type of a variable cannot be changed once created; its name, restriction and default value can.

### Use a variable in a widget

When you edit the filters of a widget on a dashboard that holds variables, the value list of a filter starts with a **Variables** group listing the variables compatible with that filter. For date, number and text filters, a *Fixed value / Variable* switch lets you pick a variable instead of typing a value. The filter chip then shows the name of the variable.

A widget that uses at least one variable shows a small marker in its header; its tooltip lists the variables used.

### Change a value

Click the chip of a variable in the bar to change its value. The widgets using it reload at once. The values you pick are **personal**: they are kept in your browser, for this dashboard, and reflected in the address bar so that a shared link opens the same view. Other users keep their own values, and the dashboard itself is not modified.

- **Reset** brings every value, and the time range, back to your default preset (see [Default preset](#default-preset)) or, without one, to the defaults of the dashboard.
- **Set as default values** (editors only) saves your current values and time range as the new defaults for everyone.

A variable no widget uses is shown muted. If a variable is deleted while widgets still use it, those widgets show *No data has been found* rather than ignoring the filter: edit their filters to pick another variable or a fixed value. The values the presets held for that variable are dropped.

### Time range

Changing the time range of a dashboard no longer modifies the dashboard: like the variable values, the range is personal and kept in your browser. Editors promote their range with **Set as default values**.

!!! warning "Behaviour change"

    Before this feature, changing the time range of a dashboard was saved immediately and applied to every user. It is now a personal setting: the home dashboard, the dashboard export and your other browsers keep the defaults of the dashboard (or your default preset); the publication form starts from the range you see. Use **Set as default values** to change the range of the dashboard for everyone.

## Presets

A preset is a named snapshot of the values of all the variables and of the time range. The preset selector sits at the start of the variables bar.

- **Save as preset** saves the current values and time range under a name. A dashboard holds up to 50 presets; names are limited to 200 characters.
- Selecting a preset restores its values and its time range at once.
- When your current values differ from the selected preset, **Update preset** (editors only) saves them into it.
- Editors can rename and delete a preset from the selector.

The selected preset is personal, like the values: it is kept in your browser and in the address bar, so sharing the address opens the same view. A value changed on top of a preset is kept apart from it: **Reset** drops it and goes back to your default preset, or to the defaults of the dashboard.

### Default preset

A dashboard can open on a preset for a given population. Wherever a default dashboard is chosen, a **Default preset** field lists the presets of that dashboard:

- in your own settings (*Custom dashboard* of the home page);
- in the settings of a group;
- in the settings of an organization.

The members then see the home dashboard, and the page of the dashboard, with the values and time range of that preset as their defaults. **Reset** brings them back to this preset. If the preset is deleted, the defaults of the dashboard apply.

When several of these settings point to the same dashboard, the first one found decides, with or without a preset: your own settings first, then your organizations, then your groups. A user who chose this dashboard with *No preset* is not caught up by the preset of their group.

## Viewer permissions

In the edition drawer of a dashboard, three switches decide what a user who can only view the dashboard may change for themselves. None of them grants any right to modify the dashboard.

| Switch | Effect for a viewer |
|---|---|
| Allow viewers to edit time filters | Shows the time filters; the range is personal |
| Allow viewers to change variable values | Shows the variables bar; the values are personal |
| Allow viewers to switch presets | Shows the preset selector |

All three are off by default: a viewer then sees the dashboard with its default values.

## Public dashboards

The publication form shows a **Published values** section: the time range and, for each variable used by a widget, the value to freeze in the public dashboard. The section starts from the values you see on the dashboard; **Load a preset** fills it from a preset. The published values are frozen at publication: the public dashboard is a snapshot, later changes of the variables or presets do not affect it. Publish the same dashboard several times to get one public dashboard per vertical.

If the author had opened *Allow viewers to edit time filters* when publishing, visitors of the public dashboard can change the time range for themselves; otherwise the time filters of the public page are disabled and show the published range, which the server enforces: the public API ignores any other range. Public dashboards published before this feature keep their behaviour (fixed range). The switch is copied at publication: republish to change it.

## Export, import and duplication

Duplicating a dashboard copies its variables and presets with it. Variables and presets are part of the dashboard export. Their entity references are converted like the ones of the widget filters, so an import on another platform resolves them when the entities exist there. Importing a single widget that uses variables into another dashboard keeps its references: a warning tells how many variables are missing, and the widget shows no data until variables with the same identifiers exist. Custom views cannot hold variables: importing such a widget into a custom view is refused.
