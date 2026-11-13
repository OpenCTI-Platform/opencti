import { FlagOutlined, MapOutlined, PlaceOutlined, PublicOutlined } from '@mui/icons-material';
import { CityVariantOutline } from 'mdi-material-ui';
import type { MenuEntry } from '../common/menus/menuEntry';
import { KNOWLEDGE } from '../../../utils/hooks/capabilities';

const knowledge = { requiredCapabilities: [KNOWLEDGE], availableInDraft: true };

// Pure data (no component import): collected by the left bar and the pages search through its `*.entries.ts(x)` name.
const menuEntries: MenuEntry[] = [
  { path: '/dashboard/locations/regions', label: 'Regions', icon: <PublicOutlined fontSize="small" />, ...knowledge },
  { path: '/dashboard/locations/countries', label: 'Countries', icon: <FlagOutlined fontSize="small" />, ...knowledge },
  { path: '/dashboard/locations/administrative_areas', label: 'Administrative areas', icon: <MapOutlined fontSize="small" />, ...knowledge },
  { path: '/dashboard/locations/cities', label: 'Cities', icon: <CityVariantOutline fontSize="small" />, ...knowledge },
  { path: '/dashboard/locations/positions', label: 'Positions', icon: <PlaceOutlined fontSize="small" />, ...knowledge },
];

export default menuEntries;
