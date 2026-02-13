import React, { useState } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  Chip,
  Divider,
  Grid,
  Tab,
  Tabs,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import { useFormatter } from '../../../../../../components/i18n';

// =====================================================
// TTP Table Data
// =====================================================

interface TTPRow {
  id: string;
  title: string;
  severity: 'High' | 'Medium' | 'Low' | 'Critical';
  severityColor: string;
  confidence: 'High' | 'Medium' | 'Low';
  confidenceColor: string;
  observations: number;
}

const TTP_ROWS: TTPRow[] = [
  { id: '1', title: 'T1071.001', severity: 'High', severityColor: '#f44336', confidence: 'High', confidenceColor: '#4caf50', observations: 3 },
  { id: '2', title: 'T1071.001', severity: 'High', severityColor: '#f44336', confidence: 'High', confidenceColor: '#4caf50', observations: 10 },
  { id: '3', title: 'T1071.001', severity: 'High', severityColor: '#ff9800', confidence: 'High', confidenceColor: '#4caf50', observations: 8 },
  { id: '4', title: 'T1071.001', severity: 'High', severityColor: '#f44336', confidence: 'High', confidenceColor: '#4caf50', observations: 7 },
  { id: '5', title: 'T1071.001', severity: 'High', severityColor: '#f44336', confidence: 'High', confidenceColor: '#4caf50', observations: 5 },
  { id: '6', title: 'T1071.001', severity: 'High', severityColor: '#f44336', confidence: 'High', confidenceColor: '#4caf50', observations: 3 },
  { id: '7', title: 'T1071.001', severity: 'High', severityColor: '#f44336', confidence: 'High', confidenceColor: '#4caf50', observations: 2 },
  { id: '8', title: 'T1071.001', severity: 'High', severityColor: '#f44336', confidence: 'High', confidenceColor: '#4caf50', observations: 2 },
  { id: '9', title: 'T1071.001', severity: 'High', severityColor: '#f44336', confidence: 'High', confidenceColor: '#4caf50', observations: 1 },
];

// =====================================================
// TTP Table (Left)
// =====================================================

const TTPTable: React.FC<{ selectedRow: string; onSelectRow: (id: string) => void }> = ({ selectedRow, onSelectRow }) => {
  const { t_i18n } = useFormatter();
  return (
    <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
      <TableContainer sx={{ flex: 1 }}>
        <Table size="small" stickyHeader>
          <TableHead>
            <TableRow>
              <TableCell padding="checkbox" sx={{ backgroundColor: 'background.paper' }}>
                <Checkbox size="small" />
              </TableCell>
              <TableCell sx={{ fontWeight: 600, fontSize: '0.8rem', backgroundColor: 'background.paper' }}>
                {t_i18n('Title')}
              </TableCell>
              <TableCell sx={{ fontWeight: 600, fontSize: '0.8rem', backgroundColor: 'background.paper' }}>
                {t_i18n('Severity')}
              </TableCell>
              <TableCell sx={{ fontWeight: 600, fontSize: '0.8rem', backgroundColor: 'background.paper' }}>
                {t_i18n('Confidence Level')}
              </TableCell>
              <TableCell sx={{ fontWeight: 600, fontSize: '0.8rem', backgroundColor: 'background.paper' }}>
                {t_i18n('Observations')}
              </TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {TTP_ROWS.map((row) => (
              <TableRow
                key={row.id}
                hover
                selected={selectedRow === row.id}
                onClick={() => onSelectRow(row.id)}
                sx={{
                  cursor: 'pointer',
                  '&.Mui-selected': { backgroundColor: 'action.selected' },
                }}
              >
                <TableCell padding="checkbox">
                  <Checkbox size="small" />
                </TableCell>
                <TableCell sx={{ fontSize: '0.8rem', fontWeight: 500 }}>{row.title}</TableCell>
                <TableCell>
                  <Chip
                    label={t_i18n(row.severity)}
                    size="small"
                    sx={{
                      height: 22,
                      fontSize: '0.7rem',
                      fontWeight: 500,
                      backgroundColor: `${row.severityColor}18`,
                      color: row.severityColor,
                      borderRadius: 1,
                    }}
                  />
                </TableCell>
                <TableCell>
                  <Chip
                    label={t_i18n(row.confidence)}
                    size="small"
                    sx={{
                      height: 22,
                      fontSize: '0.7rem',
                      fontWeight: 500,
                      backgroundColor: `${row.confidenceColor}18`,
                      color: row.confidenceColor,
                      borderRadius: 1,
                    }}
                  />
                </TableCell>
                <TableCell sx={{ fontSize: '0.8rem' }}>{row.observations}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};

// =====================================================
// TTP Detail Panel (Right)
// =====================================================

const DETAIL_TABS = ['Overview', 'Threat Knowledge', 'Content', 'Threat Factors', 'Threat Observations', 'Data'];

interface DetailFieldProps {
  label: string;
  children: React.ReactNode;
}

const DetailField: React.FC<DetailFieldProps> = ({ label, children }) => (
  <Box sx={{ marginBottom: 2.5 }}>
    <Typography variant="body2" sx={{ fontWeight: 600, fontSize: '0.8rem', color: 'text.primary', marginBottom: 0.5 }}>
      {label}
    </Typography>
    {children}
  </Box>
);

const TTPDetailPanel: React.FC = () => {
  const { t_i18n } = useFormatter();
  const [activeTab, setActiveTab] = useState(0);

  return (
    <Box
      sx={{
        flex: 1,
        minWidth: 340,
        borderLeft: '1px solid',
        borderColor: 'divider',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Title */}
      <Box sx={{ padding: 2, paddingBottom: 0 }}>
        <Typography variant="h6" sx={{ fontWeight: 700, fontSize: '1.1rem', color: 'text.primary' }}>
          T1071.001
        </Typography>
      </Box>

      {/* Tabs */}
      <Tabs
        value={activeTab}
        onChange={(_, v) => setActiveTab(v)}
        variant="scrollable"
        scrollButtons="auto"
        sx={{
          minHeight: 36,
          borderBottom: '1px solid',
          borderColor: 'divider',
          '& .MuiTab-root': {
            minHeight: 36,
            fontSize: '0.7rem',
            textTransform: 'none',
            paddingX: 1.5,
            paddingY: 0.5,
          },
        }}
      >
        {DETAIL_TABS.map((tab) => (
          <Tab key={tab} label={t_i18n(tab)} />
        ))}
      </Tabs>

      {/* Detail Content */}
      <Box sx={{ padding: 2.5, flex: 1, overflowY: 'auto' }}>
        <DetailField label={t_i18n('Tag')}>
          <Chip
            label="THREAT REPORT"
            size="small"
            sx={{
              height: 24,
              fontSize: '0.7rem',
              fontWeight: 500,
              backgroundColor: 'action.hover',
              borderRadius: 1,
            }}
          />
        </DetailField>

        <DetailField label={t_i18n('Author')}>
          <Chip
            label="AlienVault"
            size="small"
            clickable
            sx={{
              height: 24,
              fontSize: '0.7rem',
              fontWeight: 500,
              backgroundColor: '#e3f2fd',
              color: '#1565c0',
              borderRadius: 1,
            }}
          />
        </DetailField>

        <DetailField label={t_i18n('Author Confidence')}>
          <Chip
            label="Unknown"
            size="small"
            sx={{
              height: 24,
              fontSize: '0.7rem',
              fontWeight: 500,
              backgroundColor: '#f5f5f5',
              color: '#757575',
              borderRadius: 1,
            }}
          />
        </DetailField>

        <DetailField label={t_i18n('Confidence Level')}>
          <Typography variant="body2" sx={{ fontSize: '0.8rem', color: 'text.secondary' }}>
            1. Confirmed by Other Sources
          </Typography>
        </DetailField>
      </Box>

      {/* Action Button */}
      <Box sx={{ padding: 2, paddingTop: 0 }}>
        <Button
          variant="contained"
          size="small"
          sx={{
            textTransform: 'none',
            fontSize: '0.8rem',
            borderRadius: 2,
            paddingX: 2.5,
          }}
        >
          {t_i18n('More Investigation')}
        </Button>
      </Box>
    </Box>
  );
};

// =====================================================
// Main Section
// =====================================================

const TTPExplorerSection: React.FC = () => {
  const { t_i18n } = useFormatter();
  const [selectedRow, setSelectedRow] = useState('3');

  return (
    <Grid container spacing={3} sx={{ direction: 'ltr', marginTop: 1 }}>
      <Grid item xs={12}>
        <Card variant="outlined" sx={{ backgroundColor: 'background.paper' }}>
          <CardContent sx={{ padding: 3, '&:last-child': { paddingBottom: 2 } }}>
            {/* Header */}
            <Box sx={{ marginBottom: 0.5 }}>
              <Typography variant="h6" sx={{ fontWeight: 600, color: 'text.primary', fontSize: '1rem' }}>
                {t_i18n('TTP Explorer')}
              </Typography>
            </Box>
            <Typography variant="body2" sx={{ color: 'text.secondary', fontSize: '0.8rem', lineHeight: 1.5, marginBottom: 2 }}>
              {t_i18n('Shows detection techniques for a technique (e.g. T1071.001 — Web Protocols). Design cards can be used to display data linked to malware samples, indicators, and detection playbooks.')}
            </Typography>

            {/* Table + Detail Panel */}
            <Box sx={{ display: 'flex', gap: 0, minHeight: 420 }}>
              <TTPTable selectedRow={selectedRow} onSelectRow={setSelectedRow} />
              <TTPDetailPanel />
            </Box>
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );
};

export default TTPExplorerSection;
