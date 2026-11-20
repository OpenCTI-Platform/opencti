import { FlagOutlined, MapOutlined, PlaceOutlined, PublicOutlined } from '@mui/icons-material';
import { CityVariantOutline } from 'mdi-material-ui';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  {
    path: '/dashboard/locations/regions',
    label: 'Regions',
    entityType: 'Region',
    icon: <PublicOutlined fontSize="small" />,
    keywords: ['continent', 'subregion', 'geography'],
    ...knowledge,
  },
  {
    path: '/dashboard/locations/countries',
    label: 'Countries',
    entityType: 'Country',
    icon: <FlagOutlined fontSize="small" />,
    keywords: ['Country', 'nation', 'State', 'geography', 'Map'],
    ...knowledge,
  },
  {
    path: '/dashboard/locations/administrative_areas',
    label: 'Administrative areas',
    entityType: 'Administrative-Area',
    icon: <MapOutlined fontSize="small" />,
    keywords: ['State', 'province', 'county', 'department', 'district', 'geography'],
    ...knowledge,
  },
  {
    path: '/dashboard/locations/cities',
    label: 'Cities',
    entityType: 'City',
    icon: <CityVariantOutline fontSize="small" />,
    keywords: ['City', 'town', 'geolocation', 'geography'],
    ...knowledge,
  },
  {
    path: '/dashboard/locations/positions',
    label: 'Positions',
    entityType: 'Position',
    icon: <PlaceOutlined fontSize="small" />,
    keywords: ['coordinates', 'gps', 'Latitude', 'Longitude', 'address', 'geolocation'],
    ...knowledge,
  },
];

export default menuEntries;
