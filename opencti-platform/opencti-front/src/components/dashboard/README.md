# Dashboard Building Blocks

This folder contains Components, Hooks and utils useful for creating configurable
dashboards in OpenCTI.
Multiple high-level features can use these building blocks in their UIs &
workflows. Examples at the time of writing are: "Custom Dashboards" (designed as
`workspaces`of `dashboard` type) and "Custom Views".
To make this possible the design relies on Entities sharing a common set of
fields (with the same ID, and same type), see the `DashboardLike` interface.
