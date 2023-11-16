# Location

OpenCTI's Locations objects provides a comprehensive framework for representing various geographic entities within your threat intelligence data. With five distinct Location object types, you can precisely define regions, countries, areas, cities, and specific positions. This robust classification empowers you to contextualize threats geographically, enhancing the depth and accuracy of your analysis.

When you click on "Locations" in the left-side bar, you access all the "Locations" tabs, visible on the top bar on the left. By default, the user directly access the "Regions" tab, but can navigate to the other tabs as well.

From the `Locations` section, users can access the following tabs:

- `Regions`: very large geographical territories, such as a continent.
- `Countries`: the world's countries.
- `Areas`: more or less extensive geographical areas and often not having a very defined limit
- `Cities`: the world's cities.
- `Positions`: very precise positions on the globe.


## Regions

### General presentation

Regions encapsulate broader geographical territories, often representing continents or significant parts of continents. Examples include EMEA (Europe, Middle East, and Africa), Asia, Western Europe, and North America. Utilize regions to categorize large geopolitical areas and gain macro-level insights into threat patterns.

When clicking on the Regions tab at the top left, you see the list of all the Regions you have access to, in respect with your [allowed marking definitions](../administration/users.md).

![Regions list](assets/regions_list_view.png)

### Visualizing Knowledge associated with a Region

When clicking on a `Region` in the list, you land on its Overview tab. For a Region, the following tabs are accessible:

- Overview: as described [here](overview.md#overview-section), with the particularity of not having a `Details` section but a map locating the Region.
- Knowledge: a complex tab that regroups all the structured Knowledge linked to the Region. Different thematic views are proposed to easily see the related entities, the threats, the incidents, etc. linked to the Region. As described [here](overview.md#knowledge-section).
- Analyses: as described [here](overview.md#analyses-section).
- Sightings: a table containing all `Sightings` relationships corresponding to events in which an `Indicator` (IP, domain name, url, etc.) is sighted in a Region.
- Data: as described [here](overview.md#data-section).
- History: as described [here](overview.md#history-section).

![Region Overview](assets/region_overview.png)

## Countries

### General presentation

Countries represent individual nations across the world. With this object type, you can specify detailed information about a particular country, enabling precise localization of threat intelligence data. Countries are fundamental entities in geopolitical analysis, offering a focused view of activities within national borders.

When clicking on the Countries tab at the top left, you see the list of all the Countries you have access to, in respect with your [allowed marking definitions](../administration/users.md).

![Countries list](assets/countries_list_view.png)

### Visualizing Knowledge associated with a Country

When clicking on a `Country` in the list, you land on its Overview tab. For a Country, the following tabs are accessible:

- Overview: as described [here](overview.md#overview-section), with the particularity of not having a `Details` section but a map locating the Country.
- Knowledge: a complex tab that regroups all the structured Knowledge linked to the Country. Different thematic views are proposed to easily see the related entities, the threats, the incidents, etc. linked to the Country. As described [here](overview.md#knowledge-section).
- Analyses: as described [here](overview.md#analyses-section).
- Sightings: a table containing all `Sightings` relationships corresponding to events in which an `Indicator` (IP, domain name, url, etc.) is sighted in a Country.
- Data: as described [here](overview.md#data-section).
- History: as described [here](overview.md#history-section).

## Areas

### General presentation

Areas define specific geographical regions of interest, such as the Persian Gulf, the Balkans, or the Caucasus. Use areas to identify unique zones with distinct geopolitical, cultural, or strategic significance. This object type facilitates nuanced analysis of threats within defined geographic contexts.

When clicking on the Areas tab at the top left, you see the list of all the Areas you have access to, in respect with your [allowed marking definitions](../administration/users.md).

![Areas list](assets/areas_list_view.png)

### Visualizing Knowledge associated with an Area

When clicking on an `Area` in the list, you land on its Overview tab. For an Area, the following tabs are accessible:

- Overview: as described [here](overview.md#overview-section), with the particularity of not having a `Details` section but a map locating the Area.
- Knowledge: a complex tab that regroups all the structured Knowledge linked to the Area. Different thematic views are proposed to easily see the related entities, the threats, the incidents, etc. linked to the Area. As described [here](overview.md#knowledge-section).
- Analyses: as described [here](overview.md#analyses-section).
- Sightings: a table containing all `Sightings` relationships corresponding to events in which an `Indicator` (IP, domain name, url, etc.) is sighted in an Area.
- Data: as described [here](overview.md#data-section).
- History: as described [here](overview.md#history-section).


## Cities

### General presentation

Cities provide granular information about urban centers worldwide. From major metropolises to smaller towns, cities are crucial in understanding localized threat activities. With this object type, you can pinpoint threats at the urban level, aiding in tactical threat assessments and response planning.

When clicking on the Cities tab at the top left, you see the list of all the Cities you have access to, in respect with your [allowed marking definitions](../administration/users.md).

![Cities list](assets/cities_list_view.png)

### Visualizing Knowledge associated with a City

When clicking on a `City` in the list, you land on its Overview tab. For a City, the following tabs are accessible:

- Overview: as described [here](overview.md#overview-section), with the particularity of not having a `Details` section but a map locating the City.
- Knowledge: a complex tab that regroups all the structured Knowledge linked to the City. Different thematic views are proposed to easily see the related entities, the threats, the incidents, etc. linked to the City. As described [here](overview.md#knowledge-section).
- Analyses: as described [here](overview.md#analyses-section).
- Sightings: a table containing all `Sightings` relationships corresponding to events in which an `Indicator` (IP, domain name, url, etc.) is sighted in a City.
- Data: as described [here](overview.md#data-section).
- History: as described [here](overview.md#history-section).


## Positions

### General presentation

Positions represent highly precise geographical points, such as monuments, buildings, or specific event locations. This object type allows you to define exact coordinates, enabling accurate mapping of events or incidents. Positions enhance the granularity of your threat intelligence data, facilitating precise geospatial analysis.

When clicking on the Positions tab at the top left, you see the list of all the Positions you have access to, in respect with your [allowed marking definitions](../administration/users.md).

![Positions list](assets/positions_list_view.png)

### Visualizing Knowledge associated with a Position

When clicking on a `Position` in the list, you land on its Overview tab. For a Position, the following tabs are accessible:

- Overview: as described [here](overview.md#overview-section), with the particularity to display a map locating the Position.
- Knowledge: a complex tab that regroups all the structured Knowledge linked to the Position. Different thematic views are proposed to easily see the related entities, the threats, the incidents, etc. linked to the Position. As described [here](overview.md#knowledge-section).
- Analyses: as described [here](overview.md#analyses-section).
- Sightings: a table containing all `Sightings` relationships corresponding to events in which an `Indicator` (IP, domain name, url, etc.) is sighted at a Position.
- Data: as described [here](overview.md#data-section).
- History: as described [here](overview.md#history-section).
