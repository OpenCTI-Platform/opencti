import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  IconButton,
  Chip,
  Button,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Checkbox,
} from '@mui/material';
import { MoreVert } from '@mui/icons-material';
import { useFormatter } from '../../../../../../components/i18n';

const TABS = ['Overview', 'Threat Knowledge', 'Content', 'Threat Actors', 'Threat Observations', 'Data'];

const OBSERVATION_ROWS = [
  { id: 1, title: 'T1071.001', severity: 'High', confidence: 'High', observations: 13 },
  { id: 2, title: 'T1071.001', severity: 'High', confidence: 'High', observations: 10 },
  { id: 3, title: 'T1071.001', severity: 'High', confidence: 'High', observations: 8, highlighted: true },
  { id: 4, title: 'T1071.001', severity: 'High', confidence: 'High', observations: 7 },
  { id: 5, title: 'T1071.001', severity: 'High', confidence: 'High', observations: 5 },
  { id: 6, title: 'T1071.001', severity: 'High', confidence: 'High', observations: 3 },
  { id: 7, title: 'T1071.001', severity: 'High', confidence: 'High', observations: 2 },
  { id: 8, title: 'T1071.001', severity: 'High', confidence: 'High', observations: 2 },
  { id: 9, title: 'T1071.001', severity: 'High', confidence: 'High', observations: 1 },
  { id: 10, title: 'T1071.001', severity: 'High', confidence: 'High', observations: 1 },
];

const TTPExplorerSection: React.FC = () => {
  const { t_i18n } = useFormatter();
  const [activeTab, setActiveTab] = useState(0);

  return (
    <Card variant="outlined" sx={{ marginTop: 3, backgroundColor: 'background.paper' }}>
      <CardContent sx={{ p: 3 }}>
        <Box sx={{ direction: 'ltr' }}>
          {/* Header */}
          <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', mb: 2 }}>
            <Box>
              <Typography variant="h6" sx={{ fontWeight: 600 }}>
                {t_i18n('TTP Explorer')}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                {t_i18n('For a technique (e.g., T1071.001 - Web Protocols), to show examples, signatures, malware samples, and detection methods, the designed card can be used to display data linked to malware samples, indicators, and diagnostic playbooks.')}
              </Typography>
            </Box>
            <IconButton size="small" sx={{ color: 'text.secondary' }}>
              <MoreVert />
            </IconButton>
          </Box>

          {/* Two Column Layout */}
          <Box sx={{ display: 'flex', flexDirection: { xs: 'column', md: 'row' }, gap: 3 }}>
            {/* Left Column: Observations Table */}
            <Box sx={{ flex: 1, minWidth: 0 }}>
              <TableContainer sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1 }}>
                <Table size="small" stickyHeader>
                  <TableHead>
                    <TableRow>
                      <TableCell padding="checkbox">
                        <Checkbox size="small" />
                      </TableCell>
                      <TableCell>{t_i18n('Title')}</TableCell>
                      <TableCell>{t_i18n('Severity')}</TableCell>
                      <TableCell>{t_i18n('Confidence Level')}</TableCell>
                      <TableCell>{t_i18n('Number of Observations')}</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {OBSERVATION_ROWS.map((row) => (
                      <TableRow
                        key={row.id}
                        sx={{
                          bgcolor: row.highlighted ? 'action.selected' : 'transparent',
                          '&:hover': { bgcolor: 'action.hover' },
                        }}
                      >
                        <TableCell padding="checkbox">
                          <Checkbox size="small" />
                        </TableCell>
                        <TableCell>{row.title}</TableCell>
                        <TableCell>
                          <Chip label={row.severity} size="small" sx={{ bgcolor: '#ff9800', color: '#fff', height: 20, fontSize: '0.7rem' }} />
                        </TableCell>
                        <TableCell>
                          <Chip label={row.confidence} size="small" sx={{ bgcolor: '#2e7d32', color: '#fff', height: 20, fontSize: '0.7rem' }} />
                        </TableCell>
                        <TableCell>{row.observations}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>

            {/* Right Column: TTP Details */}
            <Box sx={{ flex: 1, minWidth: 0 }}>
              <Card variant="outlined" sx={{ backgroundColor: 'background.paper' }}>
                <CardContent sx={{ p: 2 }}>
                  <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
                    T1071.001
                  </Typography>
                  
                  {/* Tabs */}
                  <Tabs
                    value={activeTab}
                    onChange={(_, v) => setActiveTab(v)}
                    variant="scrollable"
                    scrollButtons="auto"
                    sx={{ mb: 2, borderBottom: 1, borderColor: 'divider' }}
                  >
                    {TABS.map((tab, i) => (
                      <Tab key={i} label={t_i18n(tab)} sx={{ minWidth: 'auto', px: 1, fontSize: '0.75rem' }} />
                    ))}
                  </Tabs>

                  {/* Details Fields */}
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 0.5 }}>
                      {t_i18n('Tag')}
                    </Typography>
                    <Chip label="THREAT REPORT" size="small" sx={{ bgcolor: '#9e9e9e', color: '#fff', height: 24, fontSize: '0.75rem' }} />
                  </Box>

                  <Box sx={{ mb: 2 }}>
                    <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 0.5 }}>
                      {t_i18n('Author')}
                    </Typography>
                    <Chip
                      label="AlienVault"
                      size="small"
                      component="button"
                      clickable
                      sx={{
                        bgcolor: '#1976d2',
                        color: '#fff',
                        height: 24,
                        fontSize: '0.75rem',
                        cursor: 'pointer',
                        '&:hover': { bgcolor: '#1565c0' },
                      }}
                    />
                  </Box>

                  <Box sx={{ mb: 2 }}>
                    <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 0.5 }}>
                      {t_i18n('Author Credibility')}
                    </Typography>
                    <Chip label="Unknown" size="small" sx={{ bgcolor: '#9e9e9e', color: '#fff', height: 24, fontSize: '0.75rem' }} />
                  </Box>

                  <Box sx={{ mb: 3 }}>
                    <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 0.5 }}>
                      {t_i18n('Confidence Level')}
                    </Typography>
                    <Chip label="1. Confirmed by Other Sources" size="small" sx={{ bgcolor: '#2e7d32', color: '#fff', height: 24, fontSize: '0.75rem' }} />
                  </Box>

                  <Button
                    variant="contained"
                    fullWidth
                    sx={{
                      bgcolor: '#9c27b0',
                      color: '#fff',
                      '&:hover': { bgcolor: '#7b1fa2' },
                      textTransform: 'none',
                    }}
                  >
                    {t_i18n('Review More')}
                  </Button>
                </CardContent>
              </Card>
            </Box>
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
};

export default TTPExplorerSection;
