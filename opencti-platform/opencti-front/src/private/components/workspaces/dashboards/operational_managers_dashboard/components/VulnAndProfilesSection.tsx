import React from 'react';
import {
  Avatar,
  Box,
  Card,
  CardContent,
  Checkbox,
  Chip,
  Divider,
  Grid,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  Typography,
} from '@mui/material';
import {
  MoreVert,
  StarBorder as StarIcon,
  ChevronRight as ChevronRightIcon,
} from '@mui/icons-material';
import { useFormatter } from '../../../../../../components/i18n';

// =====================================================
// 1. Vulnerability Prioritization Table (Left)
// =====================================================

const TAG_COLORS: Record<string, string> = {
  Healthcare: '#4caf50',
  Iran: '#f44336',
  APT: '#e91e63',
  CVE: '#ff9800',
  'node.js': '#66bb6a',
  Ransomware: '#9c27b0',
  Digikala: '#42a5f5',
  Karestan: '#ef6c00',
  Report: '#78909c',
  Breach: '#e91e63',
};

interface VulnTag { label: string; color: string; }
interface VulnRow {
  id: string; title: string; attacker: string; source: string;
  tags: VulnTag[]; pubDate: string; regDate: string;
}

const VULNS: VulnRow[] = [
  { id: '1', title: 'CVE.2025.234581', attacker: 'Qiyam', source: 'Dark Web', tags: [{ label: 'Report', color: TAG_COLORS.Report }, { label: 'Breach', color: TAG_COLORS.Breach }], pubDate: '10 days ago', regDate: 'Yesterday' },
  { id: '2', title: 'CVE.2025.234581', attacker: 'Tapndegan', source: 'Russian Market', tags: [{ label: 'Ransomware', color: TAG_COLORS.Ransomware }], pubDate: 'Last week', regDate: '60 days ago' },
  { id: '3', title: 'CVE.2025.234581', attacker: 'Qiam', source: 'Human Analyst', tags: [{ label: 'CVE', color: TAG_COLORS.CVE }, { label: 'node.js', color: TAG_COLORS['node.js'] }], pubDate: '25 Nov 2024', regDate: '30 Nov 2024' },
  { id: '4', title: 'CVE.2025.234581', attacker: 'Qiam', source: 'Human Analyst', tags: [{ label: 'Healthcare', color: TAG_COLORS.Healthcare }, { label: 'Iran', color: TAG_COLORS.Iran }, { label: 'APT', color: TAG_COLORS.APT }], pubDate: '20 Dec 2024', regDate: '23 Dec 2024' },
  { id: '5', title: 'CVE.2025.234581', attacker: 'Tapndegan', source: 'Russian Market', tags: [{ label: 'Ransomware', color: TAG_COLORS.Ransomware }], pubDate: '13 Jan 2025', regDate: '6 Jan 2025' },
  { id: '6', title: 'CVE.2025.234581', attacker: 'Qiam', source: 'Human Analyst', tags: [{ label: 'Healthcare', color: TAG_COLORS.Healthcare }, { label: 'Iran', color: TAG_COLORS.Iran }, { label: 'APT', color: TAG_COLORS.APT }], pubDate: '25 Jul 2024', regDate: '25 Jul 2024' },
  { id: '7', title: 'CVE.2025.234581', attacker: 'Qiam', source: 'Human Analyst', tags: [{ label: 'CVE', color: TAG_COLORS.CVE }, { label: 'node.js', color: TAG_COLORS['node.js'] }], pubDate: 'Last week', regDate: '3 days ago' },
  { id: '8', title: 'CVE.2025.234581', attacker: 'Qiam', source: 'Human Analyst', tags: [{ label: 'Healthcare', color: TAG_COLORS.Healthcare }, { label: 'Iran', color: TAG_COLORS.Iran }, { label: 'APT', color: TAG_COLORS.APT }], pubDate: '25 Jul 2024', regDate: '25 Jul 2024' },
  { id: '9', title: 'CVE.2025.234581', attacker: 'Tapndegan', source: 'Russian Market', tags: [{ label: 'Ransomware', color: TAG_COLORS.Ransomware }], pubDate: 'Last week', regDate: '2 days ago' },
];

const VulnTable: React.FC = () => {
  const { t_i18n } = useFormatter();
  return (
    <Card variant="outlined" sx={{ height: '100%', backgroundColor: 'background.paper', display: 'flex', flexDirection: 'column' }}>
      <CardContent sx={{ flex: 1, display: 'flex', flexDirection: 'column', padding: 3, position: 'relative', '&:last-child': { paddingBottom: 2 } }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 0.5 }}>
          <Typography variant="h6" sx={{ fontWeight: 600, color: 'text.primary', fontSize: '1rem' }}>
            {t_i18n('Vulnerability Prioritization')}
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, cursor: 'pointer', color: 'text.secondary', '&:hover': { color: 'primary.main' } }}>
            <Typography variant="body2" sx={{ fontSize: '0.8rem' }}>{t_i18n('View all')}</Typography>
            <MoreVert sx={{ fontSize: 16 }} />
          </Box>
        </Box>
        <Typography variant="body2" sx={{ color: 'text.secondary', fontSize: '0.8rem', lineHeight: 1.5, marginBottom: 2 }}>
          {t_i18n('Displays published vulnerabilities with valid patches along with coverage spread in each sector')}
        </Typography>

        <TableContainer sx={{ flex: 1 }}>
          <Table size="small" stickyHeader>
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 600, fontSize: '0.75rem', backgroundColor: 'background.paper' }}>{t_i18n('Title')}</TableCell>
                <TableCell sx={{ fontWeight: 600, fontSize: '0.75rem', backgroundColor: 'background.paper' }}>{t_i18n('Attacker')}</TableCell>
                <TableCell sx={{ fontWeight: 600, fontSize: '0.75rem', backgroundColor: 'background.paper' }}>{t_i18n('Source')}</TableCell>
                <TableCell sx={{ fontWeight: 600, fontSize: '0.75rem', backgroundColor: 'background.paper' }}>{t_i18n('Tags')}</TableCell>
                <TableCell sx={{ fontWeight: 600, fontSize: '0.75rem', backgroundColor: 'background.paper' }}>{t_i18n('Pub. Date')}</TableCell>
                <TableCell sx={{ fontWeight: 600, fontSize: '0.75rem', backgroundColor: 'background.paper' }}>
                  <TableSortLabel active direction="desc">{t_i18n('Reg. Date')}</TableSortLabel>
                </TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {VULNS.map((v) => (
                <TableRow key={v.id} hover>
                  <TableCell sx={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>{v.title}</TableCell>
                  <TableCell sx={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>{v.attacker}</TableCell>
                  <TableCell sx={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>{v.source}</TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                      {v.tags.map((tag, i) => (
                        <Chip key={`${tag.label}-${i}`} label={t_i18n(tag.label)} size="small"
                          sx={{ height: 20, fontSize: '0.6rem', fontWeight: 500, backgroundColor: `${tag.color}18`, color: tag.color, borderRadius: 1, border: `1px solid ${tag.color}40` }} />
                      ))}
                    </Box>
                  </TableCell>
                  <TableCell sx={{ fontSize: '0.75rem', color: 'text.secondary', whiteSpace: 'nowrap' }}>{v.pubDate}</TableCell>
                  <TableCell sx={{ fontSize: '0.75rem', color: 'text.secondary', whiteSpace: 'nowrap' }}>{v.regDate}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </CardContent>
    </Card>
  );
};

// =====================================================
// 2. Attacker Profiles (Right)
// =====================================================

interface AttackerProfile {
  name: string;
  date: string;
  method: string;
  otherMethods: string;
  targets: string[];
  countries: string[];
  tags: { label: string; color: string }[];
}

const ATTACKERS: AttackerProfile[] = [
  {
    name: 'Adle Ali',
    date: 'Dec 2024',
    method: 'Persian Warrior',
    otherMethods: 'APT28',
    targets: ['Healthcare'],
    countries: ['Iraq', 'Iran'],
    tags: [{ label: 'node.js', color: '#66bb6a' }, { label: 'Report', color: '#78909c' }],
  },
  {
    name: 'Tapandegan',
    date: 'Dec 2024',
    method: 'Persian Warrior',
    otherMethods: 'APT28',
    targets: ['Healthcare'],
    countries: ['Iraq', 'Iran'],
    tags: [{ label: 'node.js', color: '#66bb6a' }, { label: 'Report', color: '#78909c' }],
  },
  {
    name: 'Gonjeshke Darande',
    date: 'Nov 2024',
    method: 'Persian Warrior',
    otherMethods: 'APT28',
    targets: ['Healthcare'],
    countries: ['Iraq', 'Iran'],
    tags: [{ label: 'node.js', color: '#66bb6a' }],
  },
  {
    name: 'APT36',
    date: 'Dec 2024',
    method: 'Persian Warrior',
    otherMethods: 'APT28',
    targets: ['Healthcare'],
    countries: ['Iraq', 'Iran'],
    tags: [{ label: 'node.js', color: '#66bb6a' }, { label: 'MalDoc', color: '#ff9800' }],
  },
];

const AttackerCard: React.FC<{ attacker: AttackerProfile }> = ({ attacker }) => {
  const { t_i18n } = useFormatter();
  return (
    <Card variant="outlined" sx={{ backgroundColor: 'background.paper', '&:hover': { boxShadow: 1 } }}>
      <CardContent sx={{ padding: 2, '&:last-child': { paddingBottom: 1.5 } }}>
        {/* Header */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, marginBottom: 1.5 }}>
          <Avatar sx={{ width: 38, height: 38, fontSize: '0.85rem', backgroundColor: 'primary.main' }}>
            {attacker.name.charAt(0)}
          </Avatar>
          <Box sx={{ flex: 1 }}>
            <Typography variant="body2" sx={{ fontWeight: 600, fontSize: '0.8rem', color: 'text.primary' }}>{attacker.name}</Typography>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.65rem' }}>{attacker.date}</Typography>
          </Box>
          <IconButton size="small" sx={{ color: 'text.secondary' }}><StarIcon sx={{ fontSize: 18 }} /></IconButton>
        </Box>

        {/* Details */}
        <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 0.8, marginBottom: 1 }}>
          <Box>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.6rem' }}>{t_i18n('Attack Method')}</Typography>
            <Typography variant="body2" sx={{ fontSize: '0.7rem', fontWeight: 500 }}>{attacker.method}</Typography>
          </Box>
          <Box>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.6rem' }}>{t_i18n('Other Methods')}</Typography>
            <Typography variant="body2" sx={{ fontSize: '0.7rem', fontWeight: 500 }}>{attacker.otherMethods}</Typography>
          </Box>
          <Box>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.6rem' }}>{t_i18n('Objectives')}</Typography>
            <Box sx={{ display: 'flex', gap: 0.3, flexWrap: 'wrap' }}>
              {attacker.targets.map((t) => (
                <Chip key={t} label={t_i18n(t)} size="small"
                  sx={{ height: 18, fontSize: '0.55rem', backgroundColor: '#e8f5e9', color: '#2e7d32', borderRadius: 0.5 }} />
              ))}
            </Box>
          </Box>
          <Box>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.6rem' }}>{t_i18n('Target Countries')}</Typography>
            <Box sx={{ display: 'flex', gap: 0.3, flexWrap: 'wrap' }}>
              {attacker.countries.map((c) => (
                <Chip key={c} label={t_i18n(c)} size="small"
                  sx={{ height: 18, fontSize: '0.55rem', backgroundColor: '#e3f2fd', color: '#1565c0', borderRadius: 0.5 }} />
              ))}
            </Box>
          </Box>
        </Box>

        {/* Tags */}
        <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.6rem' }}>{t_i18n('Tags')}</Typography>
        <Box sx={{ display: 'flex', gap: 0.3, flexWrap: 'wrap', marginBottom: 1, marginTop: 0.3 }}>
          {attacker.tags.map((tag, i) => (
            <Chip key={`${tag.label}-${i}`} label={tag.label} size="small"
              sx={{ height: 18, fontSize: '0.55rem', backgroundColor: `${tag.color}18`, color: tag.color, borderRadius: 0.5, border: `1px solid ${tag.color}40` }} />
          ))}
        </Box>

        {/* More Details */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.3, color: 'text.secondary', cursor: 'pointer', '&:hover': { color: 'primary.main' } }}>
          <Typography variant="caption" sx={{ fontSize: '0.7rem' }}>{t_i18n('More details')}</Typography>
          <ChevronRightIcon sx={{ fontSize: 14 }} />
        </Box>
      </CardContent>
    </Card>
  );
};

const AttackerProfiles: React.FC = () => {
  const { t_i18n } = useFormatter();
  return (
    <Card variant="outlined" sx={{ height: '100%', backgroundColor: 'background.paper', display: 'flex', flexDirection: 'column' }}>
      <CardContent sx={{ flex: 1, display: 'flex', flexDirection: 'column', padding: 3, position: 'relative', '&:last-child': { paddingBottom: 2 } }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 0.5 }}>
          <Typography variant="h6" sx={{ fontWeight: 600, color: 'text.primary', fontSize: '1rem' }}>
            {t_i18n('Attacker Profiles')}
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, cursor: 'pointer', color: 'text.secondary', '&:hover': { color: 'primary.main' } }}>
            <Typography variant="body2" sx={{ fontSize: '0.8rem' }}>{t_i18n('View all')}</Typography>
            <MoreVert sx={{ fontSize: 16 }} />
          </Box>
        </Box>
        <Typography variant="body2" sx={{ color: 'text.secondary', fontSize: '0.8rem', lineHeight: 1.5, marginBottom: 2 }}>
          {t_i18n('Summary of technical profiles of APTs or hacktivists along with associated IOCs')}
        </Typography>

        <Grid container spacing={1.5}>
          {ATTACKERS.map((attacker) => (
            <Grid item xs={12} sm={6} key={attacker.name}>
              <AttackerCard attacker={attacker} />
            </Grid>
          ))}
        </Grid>
      </CardContent>
    </Card>
  );
};

// =====================================================
// Main Section
// =====================================================

const VulnAndProfilesSection: React.FC = () => {
  return (
    <Grid container spacing={3} sx={{ direction: 'ltr', marginTop: 1 }}>
      <Grid item xs={12} md={7}>
        <VulnTable />
      </Grid>
      <Grid item xs={12} md={5}>
        <AttackerProfiles />
      </Grid>
    </Grid>
  );
};

export default VulnAndProfilesSection;
