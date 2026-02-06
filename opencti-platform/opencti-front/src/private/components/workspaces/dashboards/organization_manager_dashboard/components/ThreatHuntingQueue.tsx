import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  IconButton,
  Button,
  Chip,
  Badge,
} from '@mui/material';
import { Search as SearchIcon, Add as AddIcon, KeyboardArrowDown as ArrowDownIcon } from '@mui/icons-material';
import { useFormatter } from '../../../../../../components/i18n';

type ColumnId = 'remediated' | 'contained' | 'investigation' | 'triage';

interface HuntCardData {
  id: string;
  title: string;
  tagType: string;
  tagSeverity: string;
  time: string;
  source: string;
  target: string;
  assignee: string;
}

interface ColumnConfig {
  id: ColumnId;
  labelKey: string;
  count: number;
  cards: HuntCardData[];
}

const SAMPLE_CARD: Omit<HuntCardData, 'id'> = {
  title: 'User Data Leak - Digikala',
  tagType: 'Leak',
  tagSeverity: 'High',
  time: '2 hours ago',
  source: 'Russian Market',
  target: 'Digikala',
  assignee: 'CTI Team',
};

const COLUMNS: ColumnConfig[] = [
  {
    id: 'remediated',
    labelKey: 'Remediated',
    count: 3,
    cards: [1, 2, 3].map((i) => ({ ...SAMPLE_CARD, id: `r-${i}` })),
  },
  {
    id: 'contained',
    labelKey: 'Contained',
    count: 6,
    cards: [1, 2, 3, 4, 5, 6].map((i) => ({ ...SAMPLE_CARD, id: `c-${i}` })),
  },
  {
    id: 'investigation',
    labelKey: 'Under Investigation',
    count: 1,
    cards: [{ ...SAMPLE_CARD, id: 'inv-1' }],
  },
  {
    id: 'triage',
    labelKey: 'Triage',
    count: 1,
    cards: [{ ...SAMPLE_CARD, id: 't-1' }],
  },
];

const HuntCard: React.FC<{ data: HuntCardData }> = ({ data }) => {
  const { t_i18n } = useFormatter();
  return (
    <Card
      variant="outlined"
      sx={{
        mb: 1.5,
        borderRadius: 2,
        boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
        '&:last-of-type': { mb: 0 },
      }}
    >
      <CardContent sx={{ p: 2, '&:last-child': { pb: 2 } }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1.5, gap: 1 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: '0.875rem', flex: 1 }}>
            {data.title}
          </Typography>
          <Box sx={{ display: 'flex', gap: 0.5, flexShrink: 0 }}>
            <Chip label={t_i18n(data.tagType)} size="small" sx={{ bgcolor: 'primary.main', color: 'primary.contrastText', fontSize: '0.7rem', height: 22 }} />
            <Chip label={t_i18n(data.tagSeverity)} size="small" sx={{ bgcolor: 'error.main', color: 'error.contrastText', fontSize: '0.7rem', height: 22 }} />
          </Box>
        </Box>
        <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 1, mb: 1.5 }}>
          <Box>
            <Typography variant="caption" color="text.secondary" display="block">{t_i18n('Time')}</Typography>
            <Typography variant="body2">{data.time}</Typography>
          </Box>
          <Box>
            <Typography variant="caption" color="text.secondary" display="block">{t_i18n('Source')}</Typography>
            <Typography variant="body2">{data.source}</Typography>
          </Box>
          <Box>
            <Typography variant="caption" color="text.secondary" display="block">{t_i18n('Target')}</Typography>
            <Typography variant="body2">{data.target}</Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Box>
            <Typography variant="caption" color="text.secondary" display="block">{t_i18n('Assignee')}</Typography>
            <Typography variant="body2">{data.assignee}</Typography>
          </Box>
          <Button
            size="small"
            endIcon={<ArrowDownIcon />}
            sx={{ textTransform: 'none', fontSize: '0.8rem' }}
            onClick={() => {}}
          >
            {t_i18n('Actions')}
          </Button>
        </Box>
      </CardContent>
    </Card>
  );
};

const ThreatHuntingQueue: React.FC = () => {
  const { t_i18n } = useFormatter();

  return (
    <Card
      variant="outlined"
      sx={{
        marginTop: 3,
        backgroundColor: 'background.paper',
      }}
    >
      <CardContent sx={{ p: 3 }}>
        <Box sx={{ direction: 'ltr' }}>
          <Typography variant="h6" sx={{ fontWeight: 600, mb: 0.5 }}>
            {t_i18n('Threat Hunting Queue')}
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {t_i18n('Number of remaining hunts and their coverage based on the ticketing system')}
          </Typography>
          <Box
            sx={{
              display: 'grid',
              gridTemplateColumns: {
                xs: '1fr',
                sm: 'repeat(2, 1fr)',
                md: 'repeat(4, 1fr)',
              },
              gap: 2,
              minHeight: 320,
            }}
          >
            {COLUMNS.map((col) => (
              <Box
                key={col.id}
                sx={{
                  minWidth: 0,
                  display: 'flex',
                  flexDirection: 'column',
                  bgcolor: 'grey.100',
                  borderRadius: 2,
                  p: 1.5,
                }}
              >
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
              <Badge badgeContent={col.count} color="primary" sx={{ '& .MuiBadge-badge': { right: -2, top: 2 } }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, pr: 1 }}>
                  {t_i18n(col.labelKey)}
                </Typography>
              </Badge>
              <Box>
                <IconButton size="small" sx={{ p: 0.5 }} onClick={() => {}}>
                  <SearchIcon fontSize="small" />
                </IconButton>
                <IconButton size="small" sx={{ p: 0.5 }} onClick={() => {}}>
                  <AddIcon fontSize="small" />
                </IconButton>
              </Box>
            </Box>
            <Box sx={{ flex: 1, overflowY: 'auto' }}>
              {col.cards.map((card) => (
                <HuntCard key={card.id} data={card} />
              ))}
            </Box>
          </Box>
        ))}
      </Box>
        </Box>
      </CardContent>
    </Card>
  );
};

export default ThreatHuntingQueue;
