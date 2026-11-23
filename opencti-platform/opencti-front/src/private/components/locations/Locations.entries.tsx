import { Icon } from '@filigran/design-system';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/locations/regions',
    label: 'Regions',
    entityType: 'Region',
    icon: <Icon name="custom/globe-line" size={16} />,
    keywords: ['continent', 'subregion', 'geography'],
    ...knowledge,
  },
  {
    path: '/dashboard/locations/countries',
    label: 'Countries',
    entityType: 'Country',
    icon: <Icon name="flag" size={16} />,
    keywords: ['Country', 'nation', 'State', 'geography', 'Map'],
    ...knowledge,
  },
  {
    path: '/dashboard/locations/administrative_areas',
    label: 'Administrative areas',
    entityType: 'Administrative-Area',
    icon: <Icon name="map" size={16} />,
    keywords: ['State', 'province', 'county', 'department', 'district', 'geography'],
    ...knowledge,
  },
  {
    path: '/dashboard/locations/cities',
    label: 'Cities',
    entityType: 'City',
    icon: <Icon name="custom/city" size={16} />,
    keywords: ['City', 'town', 'geolocation', 'geography'],
    ...knowledge,
  },
  {
    path: '/dashboard/locations/positions',
    label: 'Positions',
    entityType: 'Position',
    icon: <Icon name="map-pin" size={16} />,
    keywords: ['coordinates', 'gps', 'Latitude', 'Longitude', 'address', 'geolocation'],
    ...knowledge,
  },
];

export default menuEntries;
