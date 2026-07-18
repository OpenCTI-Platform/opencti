import { AssignmentOutlined, CloudSyncOutlined, DataObjectOutlined, PublishOutlined, RssFeedOutlined, TableViewOutlined, TravelExploreOutlined } from '@mui/icons-material';
import type { SvgIconComponent } from '@mui/icons-material';

export type BuiltInIntegrationKind = 'sync' | 'taxii' | 'taxii-push' | 'rss' | 'csv' | 'json' | 'form';

export const BUILT_IN_INTEGRATION_KINDS: BuiltInIntegrationKind[] = [
  'sync',
  'taxii',
  'taxii-push',
  'rss',
  'csv',
  'json',
  'form',
];

export interface BuiltInIntegrationDefinition {
  kind: BuiltInIntegrationKind;
  // i18n keys, translated at render time
  label: string;
  description: string;
  icon: SvgIconComponent;
}

// The native ingestion methods shipped with the platform, surfaced in the
// catalog next to the marketplace connectors as "Built-in" entries.
export const BUILT_IN_INTEGRATIONS: BuiltInIntegrationDefinition[] = [
  {
    kind: 'sync',
    label: 'OpenCTI Stream',
    description: 'Consume a remote OpenCTI live stream to synchronize knowledge between platforms in real time.',
    icon: CloudSyncOutlined,
  },
  {
    kind: 'taxii',
    label: 'TAXII Feed',
    description: 'Poll a TAXII 2.x collection on a schedule and ingest its STIX objects into the platform.',
    icon: TravelExploreOutlined,
  },
  {
    kind: 'taxii-push',
    label: 'TAXII Push',
    description: 'Expose a TAXII collection endpoint so external systems can push STIX data into the platform.',
    icon: PublishOutlined,
  },
  {
    kind: 'rss',
    label: 'RSS Feed',
    description: 'Watch an RSS or Atom feed and automatically create reports from newly published entries.',
    icon: RssFeedOutlined,
  },
  {
    kind: 'csv',
    label: 'CSV Feed',
    description: 'Fetch a remote CSV file on a schedule and map its columns to entities with a CSV mapper.',
    icon: TableViewOutlined,
  },
  {
    kind: 'json',
    label: 'JSON Feed',
    description: 'Query a remote JSON API on a schedule and map its payload to entities with a JSON mapper.',
    icon: DataObjectOutlined,
  },
  {
    kind: 'form',
    label: 'Form intake',
    description: 'Design structured intake forms so analysts can submit curated data into the platform.',
    icon: AssignmentOutlined,
  },
];

export const getBuiltInIntegration = (kind: string): BuiltInIntegrationDefinition | undefined => {
  return BUILT_IN_INTEGRATIONS.find((definition) => definition.kind === kind);
};

export const isBuiltInIntegrationKind = (value: string): value is BuiltInIntegrationKind => {
  return (BUILT_IN_INTEGRATION_KINDS as string[]).includes(value);
};
