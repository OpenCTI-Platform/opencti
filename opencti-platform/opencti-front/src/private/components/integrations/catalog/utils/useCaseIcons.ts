import {
  AccountBalanceOutlined,
  AutoFixHighOutlined,
  BugReportOutlined,
  CampaignOutlined,
  CloudOutlined,
  ConfirmationNumberOutlined,
  DevicesOutlined,
  DomainOutlined,
  EmailOutlined,
  GppMaybeOutlined,
  HubOutlined,
  InsightsOutlined,
  LabelOutlined,
  LanOutlined,
  PhishingOutlined,
  PublicOutlined,
  QueryStatsOutlined,
  RadarOutlined,
  RouterOutlined,
  ShieldOutlined,
  StorefrontOutlined,
  TrackChangesOutlined,
  WorkspacePremiumOutlined,
} from '@mui/icons-material';
import type { SvgIconComponent } from '@mui/icons-material';

// The catalog use-case taxonomy is now frozen: each use case gets a dedicated
// icon, matched on stable keywords so minor label rewordings keep working.
// Order matters: the first matching entry wins.
const USE_CASE_ICON_MATCHERS: [string[], SvgIconComponent][] = [
  [['adversary', 'campaign'], TrackChangesOutlined],
  [['brand', 'digital risk', 'underground'], StorefrontOutlined],
  [['cloud', 'saas', 'platform'], CloudOutlined],
  [['commercial threat'], WorkspacePremiumOutlined],
  [['detection & response', 'detection and response'], RadarOutlined],
  [['email'], EmailOutlined],
  [['endpoint'], DevicesOutlined],
  [['enrichment', 'analysis'], InsightsOutlined],
  [['influence', 'disinformation'], CampaignOutlined],
  [['fraud', 'financial'], AccountBalanceOutlined],
  [['incident response', 'ticketing'], ConfirmationNumberOutlined],
  [['infrastructure', 'attack surface'], LanOutlined],
  [['malware', 'sandbox'], BugReportOutlined],
  [['network security'], RouterOutlined],
  [['open source threat'], PublicOutlined],
  [['phishing'], PhishingOutlined],
  [['siem', 'analytics'], QueryStatsOutlined],
  [['soar', 'automation'], AutoFixHighOutlined],
  [['third-party', 'supply chain'], HubOutlined],
  [['threat intelligence'], ShieldOutlined],
  [['vertical market', 'mission'], DomainOutlined],
  [['vulnerability', 'exploit'], GppMaybeOutlined],
];

export const getUseCaseIcon = (useCase: string): SvgIconComponent => {
  const normalized = useCase.toLowerCase();
  for (const [keywords, icon] of USE_CASE_ICON_MATCHERS) {
    if (keywords.some((keyword) => normalized.includes(keyword))) {
      return icon;
    }
  }
  return LabelOutlined;
};

export default getUseCaseIcon;
