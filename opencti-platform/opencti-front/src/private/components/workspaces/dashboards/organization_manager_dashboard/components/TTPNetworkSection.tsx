import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  IconButton,
  Chip,
} from '@mui/material';
import { MoreVert, OpenInNew, ArrowDropDown } from '@mui/icons-material';
import { useFormatter } from '../../../../../../components/i18n';

const TTPNetworkSection: React.FC = () => {
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
          {/* Single column: TTP Network Graph; details card inside it on the right */}
          <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', mb: 1 }}>
            <Box>
              <Typography variant="h6" sx={{ fontWeight: 600 }}>
                {t_i18n('TTP Network Graph')}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                {t_i18n('Shows the relationships between TTPs that hacktivists use in attacks on the country.')}
              </Typography>
            </Box>
            <IconButton size="small" sx={{ color: 'text.secondary' }}>
              <MoreVert />
            </IconButton>
          </Box>
          <Box
            sx={{
              position: 'relative',
              minHeight: 400,
              borderRadius: 2,
              bgcolor: 'grey.50',
              border: '1px solid',
              borderColor: 'divider',
              overflow: 'hidden',
            }}
          >
            <Box sx={{ width: '100%', height: 400, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <TTPGraphPlaceholder />
            </Box>
            {/* Details card inside the graph area, on the left (LTR) */}
            <Card
              variant="outlined"
              sx={{
                position: 'absolute',
                left: 16,
                top: 16,
                bottom: 16,
                width: 300,
                maxWidth: 'calc(100% - 32px)',
                display: 'flex',
                flexDirection: 'column',
                backgroundColor: 'background.paper',
                boxShadow: 2,
              }}
            >
              <CardContent sx={{ flex: 1, overflow: 'auto', p: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                  <Typography variant="caption" color="text.secondary">
                    {t_i18n('Item')}
                  </Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                    <IconButton size="small" sx={{ p: 0.25 }}>
                      <OpenInNew fontSize="small" />
                    </IconButton>
                    <IconButton size="small" sx={{ p: 0.25 }}>
                      <ArrowDropDown fontSize="small" />
                    </IconButton>
                  </Box>
                </Box>
                <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 2 }}>
                  CVE-2024-36761
                </Typography>

                <DetailRow label={t_i18n('Tag')} value={<Chip label="THREAT REPORT" size="small" sx={{ height: 24, fontSize: '0.75rem', bgcolor: '#1976d2', color: '#fff' }} />} />
                <DetailRow label={t_i18n('Author')} value={<Chip label="AlienVault" size="small" sx={{ height: 24, fontSize: '0.75rem', bgcolor: '#1976d2', color: '#fff' }} />} />
                <DetailRow label={t_i18n('Author Credibility')} value={<Chip label="Unknown" size="small" sx={{ height: 24, fontSize: '0.75rem', bgcolor: '#9e9e9e', color: '#fff' }} />} />
                <DetailRow label={t_i18n('Confidence Level')} value={<Chip label="1. Confirmed by Other Sources" size="small" sx={{ height: 24, fontSize: '0.75rem', bgcolor: '#2e7d32', color: '#fff' }} />} />
                <DetailRow label={t_i18n('Last Change Date')} value="Today 09:30 AM" />
                <DetailRow label={t_i18n('Registration Date')} value="Today 08:30 AM" />
                <DetailRow label={t_i18n('Crawl Date')} value="Yesterday 09:30 PM" />
                <DetailRow label={t_i18n('Publish Date')} value="Two days ago 09:30 PM" />
              </CardContent>
            </Card>
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
};

function DetailRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <Box sx={{ mb: 2 }}>
      <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 0.5 }}>
        {label}
      </Typography>
      {typeof value === 'string' ? (
        <Typography variant="body2">{value}</Typography>
      ) : (
        value
      )}
    </Box>
  );
}

function TTPGraphPlaceholder() {
  return (
    <Box sx={{ width: '100%', height: '100%', position: 'relative' }}>
      <svg width="100%" height="100%" style={{ minHeight: 380 }}>
        <defs>
          <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
            <polygon points="0 0, 10 3.5, 0 7" fill="#2196f3" />
          </marker>
        </defs>
        {/* Simulated nodes and edges */}
        <line x1="20%" y1="30%" x2="35%" y2="25%" stroke="#2196f3" strokeWidth="1" markerEnd="url(#arrowhead)" />
        <line x1="35%" y1="25%" x2="50%" y2="35%" stroke="#2196f3" strokeWidth="1" markerEnd="url(#arrowhead)" />
        <line x1="50%" y1="35%" x2="65%" y2="30%" stroke="#2196f3" strokeWidth="1" markerEnd="url(#arrowhead)" />
        <line x1="40%" y1="50%" x2="50%" y2="35%" stroke="#2196f3" strokeWidth="1" markerEnd="url(#arrowhead)" />
        <line x1="60%" y1="55%" x2="65%" y2="30%" stroke="#2196f3" strokeWidth="1" markerEnd="url(#arrowhead)" />
        <circle cx="20%" cy="30%" r="14" fill="#f44336" stroke="#c62828" strokeWidth="2" />
        <circle cx="35%" cy="25%" r="14" fill="#4caf50" stroke="#2e7d32" strokeWidth="2" />
        <circle cx="50%" cy="35%" r="20" fill="#ff9800" stroke="#e65100" strokeWidth="2" />
        <circle cx="65%" cy="30%" r="14" fill="#ffeb3b" stroke="#f9a825" strokeWidth="2" />
        <circle cx="40%" cy="50%" r="12" fill="#ffeb3b" stroke="#f9a825" strokeWidth="2" />
        <circle cx="60%" cy="55%" r="12" fill="#ffeb3b" stroke="#f9a825" strokeWidth="2" />
        <text x="50%" y="35%" textAnchor="middle" dominantBaseline="middle" fontSize="10" fill="#fff" fontWeight="bold">TTP</text>
      </svg>
    </Box>
  );
}

export default TTPNetworkSection;
