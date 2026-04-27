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

interface HuntCard {
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
  cards: HuntCard[];
}

// =====================================================
// Sample Data
// =====================================================

const makeCard = (id: string): HuntCard => ({
  id,
  title: 'User Data Breach - Digikala',
  severity: 'High',
  status: 'Active',
  assignee: 'CTI Team',
  source: 'Russian Market',
  time: '2 hours ago',
  target: 'Digikala',
});

const COLUMNS: KanbanColumn[] = [
  {
    id: 'triage',
    title: 'Triage',
    color: '#ef5350',
    cards: [makeCard('t1'), makeCard('t2'), makeCard('t3')],
  },
  {
    id: 'investigation',
    title: 'Under Investigation',
    color: '#42a5f5',
    cards: [makeCard('i1'), makeCard('i2'), makeCard('i3')],
  },
  {
    id: 'contained',
    title: 'Contained',
    color: '#66bb6a',
    cards: [makeCard('c1'), makeCard('c2'), makeCard('c3')],
  },
  {
    id: 'remediated',
    title: 'Remediated',
    color: '#9e9e9e',
    cards: [makeCard('r1'), makeCard('r2')],
  },
];

// =====================================================
// Hunt Card Component
// =====================================================

const HuntCardItem: React.FC<{ card: HuntCard }> = ({ card }) => {
  const { t_i18n } = useFormatter();

  const severityColor = {
    Critical: '#d32f2f',
    High: '#ef5350',
    Medium: '#ff9800',
    Low: '#4caf50',
  }[card.severity];

  return (
    <Card
      variant="outlined"
      sx={{
        backgroundColor: 'background.paper',
        borderRadius: 1.5,
        '&:hover': { boxShadow: 1 },
      }}
    >
      <CardContent sx={{ padding: 2, '&:last-child': { paddingBottom: 1.5 } }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 1.5 }}>
          <Typography
            variant="body2"
            sx={{ fontWeight: 600, color: 'text.primary', fontSize: '0.85rem', flex: 1 }}
          >
            {card.title}
          </Typography>
          <Box sx={{ display: 'flex', gap: 0.5, marginInlineStart: 1, flexShrink: 0 }}>
            <Chip
              label={t_i18n(card.severity)}
              size="small"
              sx={{
                height: 20, fontSize: '0.65rem', fontWeight: 600,
                backgroundColor: `${severityColor}18`, color: severityColor, borderRadius: 1,
              }}
            />
            <Chip
              label={t_i18n(card.status)}
              size="small"
              sx={{
                height: 20, fontSize: '0.65rem', fontWeight: 600,
                backgroundColor: 'primary.lighter', color: 'primary.main', borderRadius: 1,
              }}
            />
          </Box>
        </Box>

        <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1, marginBottom: 1.5 }}>
          <Box>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.65rem' }}>{t_i18n('Target')}</Typography>
            <Typography variant="body2" sx={{ color: 'text.primary', fontSize: '0.75rem', fontWeight: 500 }}>{card.target}</Typography>
          </Box>
          <Box>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.65rem' }}>{t_i18n('Source')}</Typography>
            <Typography variant="body2" sx={{ color: 'text.primary', fontSize: '0.75rem', fontWeight: 500 }}>{card.source}</Typography>
          </Box>
          <Box>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.65rem' }}>{t_i18n('Time')}</Typography>
            <Typography variant="body2" sx={{ color: 'text.primary', fontSize: '0.75rem', fontWeight: 500 }}>{card.time}</Typography>
          </Box>
          <Box>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.65rem' }}>{t_i18n('Assignee')}</Typography>
            <Typography variant="body2" sx={{ color: 'text.primary', fontSize: '0.75rem', fontWeight: 500 }}>{card.assignee}</Typography>
          </Box>
        </Box>

        <Divider sx={{ marginBottom: 1 }} />
        <Button
          size="small"
          endIcon={<ExpandMoreIcon sx={{ fontSize: 14 }} />}
          sx={{ textTransform: 'none', fontSize: '0.75rem', color: 'text.secondary', padding: '2px 8px', minHeight: 'auto' }}
        >
          {t_i18n('Actions')}
        </Button>
      </CardContent>
    </Card>
  );
};

// =====================================================
// Column Component
// =====================================================

const KanbanColumnComponent: React.FC<{ column: KanbanColumn }> = ({ column }) => {
  const { t_i18n } = useFormatter();

  return (
    <Box
      sx={{
        flex: 1, minWidth: 260, display: 'flex', flexDirection: 'column',
        backgroundColor: 'action.hover', borderRadius: 2, overflow: 'hidden',
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: 1.5, paddingBottom: 1 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Box sx={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: column.color }} />
          <Typography variant="body2" sx={{ fontWeight: 600, color: 'text.primary', fontSize: '0.85rem' }}>
            {t_i18n(column.title)}
          </Typography>
        </Box>
        <IconButton size="small" sx={{ color: 'text.secondary' }}>
          <SearchIcon sx={{ fontSize: 16 }} />
        </IconButton>
      </Box>

      <Box sx={{ paddingX: 1.5, paddingBottom: 1 }}>
        <Button
          fullWidth variant="outlined" startIcon={<AddIcon sx={{ fontSize: 16 }} />}
          sx={{
            textTransform: 'none', fontSize: '0.75rem', color: 'text.secondary',
            borderColor: 'divider', borderStyle: 'dashed', borderRadius: 1, padding: '4px 8px',
            '&:hover': { borderColor: 'primary.main', backgroundColor: 'action.hover' },
          }}
        />
      </Box>

      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, padding: 1.5, paddingTop: 0.5, overflowY: 'auto', maxHeight: 600 }}>
        {column.cards.map((card) => (
          <HuntCardItem key={card.id} card={card} />
        ))}
      </Box>
    </Box>
  );
};

// =====================================================
// Main Section
// =====================================================

const ThreatHuntingQueueBoard: React.FC = () => {
  const { t_i18n } = useFormatter();

  return (
    <Box sx={{ marginTop: 3 }}>
      <Card
        variant="outlined"
        sx={{ backgroundColor: 'background.paper', display: 'flex', flexDirection: 'column' }}
      >
        <CardContent
          sx={{
            display: 'flex', flexDirection: 'column', padding: 3,
            position: 'relative', '&:last-child': { paddingBottom: 2 },
          }}
        >
          <IconButton
            size="small"
            sx={{ position: 'absolute', top: 8, right: 8, color: 'text.secondary' }}
            onClick={(e) => e.stopPropagation()}
          >
            <MoreVert fontSize="small" />
          </IconButton>

          <Typography variant="h6" sx={{ fontWeight: 600, color: 'text.primary', fontSize: '1rem', paddingInlineEnd: 4 }}>
            {t_i18n('Threat Hunting Queue')}
          </Typography>

          <Typography
            variant="body2"
            sx={{ color: 'text.secondary', fontSize: '0.8rem', lineHeight: 1.5, marginTop: 0.5, marginBottom: 2 }}
          >
            {t_i18n('Number of remaining hunts and their coverage based on the ticketing system')}
          </Typography>

          <Box sx={{ display: 'flex', gap: 2, overflowX: 'auto', paddingBottom: 1 }}>
            {COLUMNS.map((column) => (
              <KanbanColumnComponent key={column.id} column={column} />
            ))}
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
};

export default ThreatHuntingQueueBoard;
