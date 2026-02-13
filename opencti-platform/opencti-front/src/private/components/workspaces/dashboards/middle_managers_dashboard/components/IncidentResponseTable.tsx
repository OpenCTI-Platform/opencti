import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Chip,
  Divider,
  IconButton,
  Typography,
  Button,
} from '@mui/material';
import {
  MoreVert,
  Add as AddIcon,
  Search as SearchIcon,
  ExpandMore as ExpandMoreIcon,
} from '@mui/icons-material';
import { useFormatter } from '../../../../../../components/i18n';

// =====================================================
// Types
// =====================================================

interface IncidentCard {
  id: string;
  title: string;
  severity: 'High' | 'Medium' | 'Low' | 'Critical';
  status: 'Active' | 'Monitoring' | 'Resolved';
  assignee: string;
  source: string;
  time: string;
  target: string;
}

interface KanbanColumn {
  id: string;
  title: string;
  color: string;
  incidents: IncidentCard[];
}

// =====================================================
// Sample Data
// =====================================================

const COLUMNS: KanbanColumn[] = [
  {
    id: 'triage',
    title: 'Triage',
    color: '#ef5350',
    incidents: [
      {
        id: 't1',
        title: 'User Data Breach - Digikala',
        severity: 'High',
        status: 'Active',
        assignee: 'CTI Team',
        source: 'Russian Market',
        time: '2 hours ago',
        target: 'Digikala',
      },
      {
        id: 't2',
        title: 'User Data Breach - Digikala',
        severity: 'High',
        status: 'Active',
        assignee: 'CTI Team',
        source: 'Russian Market',
        time: '2 hours ago',
        target: 'Digikala',
      },
      {
        id: 't3',
        title: 'User Data Breach - Digikala',
        severity: 'High',
        status: 'Active',
        assignee: 'CTI Team',
        source: 'Russian Market',
        time: '2 hours ago',
        target: 'Digikala',
      },
    ],
  },
  {
    id: 'investigation',
    title: 'Under Investigation',
    color: '#42a5f5',
    incidents: [
      {
        id: 'i1',
        title: 'User Data Breach - Digikala',
        severity: 'High',
        status: 'Active',
        assignee: 'CTI Team',
        source: 'Russian Market',
        time: '2 hours ago',
        target: 'Digikala',
      },
      {
        id: 'i2',
        title: 'User Data Breach - Digikala',
        severity: 'High',
        status: 'Active',
        assignee: 'CTI Team',
        source: 'Russian Market',
        time: '2 hours ago',
        target: 'Digikala',
      },
      {
        id: 'i3',
        title: 'User Data Breach - Digikala',
        severity: 'High',
        status: 'Active',
        assignee: 'CTI Team',
        source: 'Russian Market',
        time: '2 hours ago',
        target: 'Digikala',
      },
    ],
  },
  {
    id: 'contained',
    title: 'Contained',
    color: '#66bb6a',
    incidents: [
      {
        id: 'c1',
        title: 'User Data Breach - Digikala',
        severity: 'High',
        status: 'Active',
        assignee: 'CTI Team',
        source: 'Russian Market',
        time: '2 hours ago',
        target: 'Digikala',
      },
      {
        id: 'c2',
        title: 'User Data Breach - Digikala',
        severity: 'High',
        status: 'Active',
        assignee: 'CTI Team',
        source: 'Russian Market',
        time: '2 hours ago',
        target: 'Digikala',
      },
    ],
  },
  {
    id: 'remediated',
    title: 'Remediated',
    color: '#9e9e9e',
    incidents: [
      {
        id: 'r1',
        title: 'User Data Breach - Digikala',
        severity: 'High',
        status: 'Active',
        assignee: 'CTI Team',
        source: 'Russian Market',
        time: '2 hours ago',
        target: 'Digikala',
      },
      {
        id: 'r2',
        title: 'User Data Breach - Digikala',
        severity: 'High',
        status: 'Active',
        assignee: 'CTI Team',
        source: 'Russian Market',
        time: '2 hours ago',
        target: 'Digikala',
      },
    ],
  },
];

// =====================================================
// Incident Card Component
// =====================================================

const IncidentCardItem: React.FC<{ incident: IncidentCard }> = ({ incident }) => {
  const { t_i18n } = useFormatter();

  const severityColor = {
    Critical: '#d32f2f',
    High: '#ef5350',
    Medium: '#ff9800',
    Low: '#4caf50',
  }[incident.severity];

  return (
    <Card
      variant="outlined"
      sx={{
        backgroundColor: 'background.paper',
        borderRadius: 1.5,
        '&:hover': {
          boxShadow: 1,
        },
      }}
    >
      <CardContent sx={{ padding: 2, '&:last-child': { paddingBottom: 1.5 } }}>
        {/* Title and badges */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 1.5 }}>
          <Typography
            variant="body2"
            sx={{ fontWeight: 600, color: 'text.primary', fontSize: '0.85rem', flex: 1 }}
          >
            {incident.title}
          </Typography>
          <Box sx={{ display: 'flex', gap: 0.5, marginLeft: 1, flexShrink: 0 }}>
            <Chip
              label={t_i18n(incident.severity)}
              size="small"
              sx={{
                height: 20,
                fontSize: '0.65rem',
                fontWeight: 600,
                backgroundColor: `${severityColor}18`,
                color: severityColor,
                borderRadius: 1,
              }}
            />
            <Chip
              label={t_i18n(incident.status)}
              size="small"
              sx={{
                height: 20,
                fontSize: '0.65rem',
                fontWeight: 600,
                backgroundColor: 'primary.lighter',
                color: 'primary.main',
                borderRadius: 1,
              }}
            />
          </Box>
        </Box>

        {/* Details grid */}
        <Box
          sx={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: 1,
            marginBottom: 1.5,
          }}
        >
          <Box>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.65rem' }}>
              {t_i18n('Target')}
            </Typography>
            <Typography variant="body2" sx={{ color: 'text.primary', fontSize: '0.75rem', fontWeight: 500 }}>
              {incident.target}
            </Typography>
          </Box>
          <Box>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.65rem' }}>
              {t_i18n('Source')}
            </Typography>
            <Typography variant="body2" sx={{ color: 'text.primary', fontSize: '0.75rem', fontWeight: 500 }}>
              {incident.source}
            </Typography>
          </Box>
          <Box>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.65rem' }}>
              {t_i18n('Time')}
            </Typography>
            <Typography variant="body2" sx={{ color: 'text.primary', fontSize: '0.75rem', fontWeight: 500 }}>
              {incident.time}
            </Typography>
          </Box>
          <Box>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.65rem' }}>
              {t_i18n('Assignee')}
            </Typography>
            <Typography variant="body2" sx={{ color: 'text.primary', fontSize: '0.75rem', fontWeight: 500 }}>
              {incident.assignee}
            </Typography>
          </Box>
        </Box>

        {/* Actions button */}
        <Divider sx={{ marginBottom: 1 }} />
        <Button
          size="small"
          endIcon={<ExpandMoreIcon sx={{ fontSize: 14 }} />}
          sx={{
            textTransform: 'none',
            fontSize: '0.75rem',
            color: 'text.secondary',
            padding: '2px 8px',
            minHeight: 'auto',
          }}
        >
          {t_i18n('Actions')}
        </Button>
      </CardContent>
    </Card>
  );
};

// =====================================================
// Kanban Column Component
// =====================================================

const KanbanColumnComponent: React.FC<{ column: KanbanColumn }> = ({ column }) => {
  const { t_i18n } = useFormatter();

  return (
    <Box
      sx={{
        flex: 1,
        minWidth: 260,
        display: 'flex',
        flexDirection: 'column',
        backgroundColor: 'action.hover',
        borderRadius: 2,
        overflow: 'hidden',
      }}
    >
      {/* Column Header */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: 1.5,
          paddingBottom: 1,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Box
            sx={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              backgroundColor: column.color,
            }}
          />
          <Typography
            variant="body2"
            sx={{ fontWeight: 600, color: 'text.primary', fontSize: '0.85rem' }}
          >
            {t_i18n(column.title)}
          </Typography>
        </Box>
        <IconButton size="small" sx={{ color: 'text.secondary' }}>
          <SearchIcon sx={{ fontSize: 16 }} />
        </IconButton>
      </Box>

      {/* Add button */}
      <Box sx={{ paddingX: 1.5, paddingBottom: 1 }}>
        <Button
          fullWidth
          variant="outlined"
          startIcon={<AddIcon sx={{ fontSize: 16 }} />}
          sx={{
            textTransform: 'none',
            fontSize: '0.75rem',
            color: 'text.secondary',
            borderColor: 'divider',
            borderStyle: 'dashed',
            borderRadius: 1,
            padding: '4px 8px',
            '&:hover': {
              borderColor: 'primary.main',
              backgroundColor: 'action.hover',
            },
          }}
        />
      </Box>

      {/* Incident Cards */}
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          gap: 1,
          padding: 1.5,
          paddingTop: 0.5,
          overflowY: 'auto',
          maxHeight: 600,
        }}
      >
        {column.incidents.map((incident) => (
          <IncidentCardItem key={incident.id} incident={incident} />
        ))}
      </Box>
    </Box>
  );
};

// =====================================================
// Main Section
// =====================================================

const IncidentResponseTable: React.FC = () => {
  const { t_i18n } = useFormatter();

  return (
    <Box sx={{ marginTop: 3 }}>
      <Card
        variant="outlined"
        sx={{
          backgroundColor: 'background.paper',
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        <CardContent
          sx={{
            display: 'flex',
            flexDirection: 'column',
            padding: 3,
            position: 'relative',
            '&:last-child': { paddingBottom: 2 },
          }}
        >
          <IconButton
            size="small"
            sx={{ position: 'absolute', top: 8, right: 8, color: 'text.secondary' }}
            onClick={(e) => e.stopPropagation()}
          >
            <MoreVert fontSize="small" />
          </IconButton>

          <Typography
            variant="h6"
            sx={{ fontWeight: 600, color: 'text.primary', fontSize: '1rem', paddingRight: 4 }}
          >
            {t_i18n('Incident Response Table')}
          </Typography>

          <Typography
            variant="body2"
            sx={{
              color: 'text.secondary',
              fontSize: '0.8rem',
              lineHeight: 1.5,
              marginTop: 0.5,
              marginBottom: 2,
            }}
          >
            {t_i18n('Displays list of active incidents with current status related to hacktivist groups and active attackers')}
          </Typography>

          {/* Kanban Board */}
          <Box
            sx={{
              display: 'flex',
              gap: 2,
              overflowX: 'auto',
              paddingBottom: 1,
            }}
          >
            {COLUMNS.map((column) => (
              <KanbanColumnComponent key={column.id} column={column} />
            ))}
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
};

export default IncidentResponseTable;
