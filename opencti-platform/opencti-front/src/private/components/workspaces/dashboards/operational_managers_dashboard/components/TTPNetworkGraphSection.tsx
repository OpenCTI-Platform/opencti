import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Chip,
  Divider,
  IconButton,
  Typography,
} from '@mui/material';
import {
  MoreVert,
  OpenInNew as OpenInNewIcon,
  ExpandMore as ExpandMoreIcon,
} from '@mui/icons-material';
import { useFormatter } from '../../../../../../components/i18n';

// =====================================================
// Detail Field Component
// =====================================================

interface DetailFieldProps {
  label: string;
  children: React.ReactNode;
}

const DetailField: React.FC<DetailFieldProps> = ({ label, children }) => {
  const { t_i18n } = useFormatter();
  return (
    <Box sx={{ paddingY: 1.5 }}>
      <Typography
        variant="body2"
        sx={{ fontWeight: 600, color: 'text.primary', fontSize: '0.85rem', marginBottom: 0.5 }}
      >
        {t_i18n(label)}
      </Typography>
      {children}
    </Box>
  );
};

// =====================================================
// Network Graph Placeholder (Left Panel)
// =====================================================

const NetworkGraphPlaceholder: React.FC = () => {
  const { t_i18n } = useFormatter();

  // Simulated nodes for visual placeholder
  const nodes = [
    { x: 150, y: 120, r: 18, label: 'T1566', color: '#5c6bc0' },
    { x: 300, y: 80, r: 14, label: 'T1190', color: '#42a5f5' },
    { x: 250, y: 200, r: 20, label: 'T1059', color: '#ef5350' },
    { x: 400, y: 150, r: 16, label: 'T1078', color: '#ff9800' },
    { x: 100, y: 250, r: 12, label: 'T1055', color: '#66bb6a' },
    { x: 350, y: 280, r: 15, label: 'T1021', color: '#ab47bc' },
    { x: 500, y: 100, r: 13, label: 'T1071', color: '#26a69a' },
    { x: 200, y: 320, r: 17, label: 'T1486', color: '#d32f2f' },
    { x: 450, y: 250, r: 14, label: 'T1027', color: '#7e57c2' },
    { x: 550, y: 200, r: 11, label: 'T1082', color: '#78909c' },
  ];

  const edges = [
    [0, 1], [0, 2], [1, 3], [2, 4], [2, 5], [3, 6],
    [4, 7], [5, 8], [6, 9], [1, 5], [3, 8], [7, 5],
  ];

  return (
    <Box
      sx={{
        flex: 1,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: 400,
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <svg width="100%" height="400" viewBox="0 0 650 400">
        {/* Edges */}
        {edges.map(([from, to], idx) => (
          <line
            key={`edge-${idx}`}
            x1={nodes[from].x}
            y1={nodes[from].y}
            x2={nodes[to].x}
            y2={nodes[to].y}
            stroke="rgba(150,150,150,0.25)"
            strokeWidth="1.5"
          />
        ))}
        {/* Nodes */}
        {nodes.map((node, idx) => (
          <g key={`node-${idx}`}>
            <circle
              cx={node.x}
              cy={node.y}
              r={node.r}
              fill={node.color}
              opacity={0.85}
            />
            <text
              x={node.x}
              y={node.y + 4}
              textAnchor="middle"
              fill="white"
              fontSize="8"
              fontWeight="600"
              fontFamily="IBM Plex Sans, sans-serif"
            >
              {node.label}
            </text>
          </g>
        ))}
      </svg>
    </Box>
  );
};

// =====================================================
// Detail Panel (Right Panel)
// =====================================================

const DetailPanel: React.FC = () => {
  const { t_i18n } = useFormatter();

  return (
    <Box
      sx={{
        width: 320,
        minWidth: 280,
        borderRight: '1px solid',
        borderColor: 'divider',
        paddingRight: 3,
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Item */}
      <DetailField label="Item">
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <IconButton size="small" sx={{ color: 'text.secondary' }}>
            <OpenInNewIcon sx={{ fontSize: 16 }} />
          </IconButton>
          <IconButton size="small" sx={{ color: 'text.secondary' }}>
            <ExpandMoreIcon sx={{ fontSize: 16 }} />
          </IconButton>
          <Typography variant="body2" sx={{ fontSize: '0.85rem', color: 'text.primary', fontWeight: 500 }}>
            CVE-202436761
          </Typography>
        </Box>
      </DetailField>
      <Divider />

      {/* Tag */}
      <DetailField label="Tag">
        <Chip
          label="THREAT REPORT"
          size="small"
          sx={{
            height: 24,
            fontSize: '0.7rem',
            fontWeight: 600,
            backgroundColor: '#e8f5e9',
            color: '#2e7d32',
            borderRadius: 1,
          }}
        />
      </DetailField>
      <Divider />

      {/* Author */}
      <DetailField label="Author">
        <Chip
          label="AlienVault"
          size="small"
          variant="outlined"
          sx={{
            height: 24,
            fontSize: '0.75rem',
            borderRadius: 1,
          }}
        />
      </DetailField>
      <Divider />

      {/* Author Reliability */}
      <DetailField label="Author Reliability">
        <Chip
          label="Unknown"
          size="small"
          variant="outlined"
          sx={{
            height: 24,
            fontSize: '0.75rem',
            borderRadius: 1,
          }}
        />
      </DetailField>
      <Divider />

      {/* Confidence Level */}
      <DetailField label="Confidence Level">
        <Chip
          label="1. Confirmed by Other Sources"
          size="small"
          sx={{
            height: 24,
            fontSize: '0.7rem',
            fontWeight: 500,
            backgroundColor: '#e8f5e9',
            color: '#2e7d32',
            border: '1px solid #4caf50',
            borderRadius: 1,
          }}
        />
      </DetailField>
      <Divider />

      {/* Last Modified Date */}
      <DetailField label="Last Modified Date">
        <Typography variant="body2" sx={{ fontSize: '0.8rem', color: 'text.secondary' }}>
          Today at 9:30 AM
        </Typography>
      </DetailField>
      <Divider />

      {/* Registration Date */}
      <DetailField label="Registration Date">
        <Typography variant="body2" sx={{ fontSize: '0.8rem', color: 'text.secondary' }}>
          Today at 9:30 AM
        </Typography>
      </DetailField>
      <Divider />

      {/* Created Date */}
      <DetailField label="Created Date">
        <Typography variant="body2" sx={{ fontSize: '0.8rem', color: 'text.secondary' }}>
          Yesterday at 9:30 PM
        </Typography>
      </DetailField>
      <Divider />

      {/* Publication Date */}
      <DetailField label="Publication Date">
        <Typography variant="body2" sx={{ fontSize: '0.8rem', color: 'text.secondary' }}>
          2 days ago at 9:30 PM
        </Typography>
      </DetailField>
    </Box>
  );
};

// =====================================================
// Main Section
// =====================================================

const TTPNetworkGraphSection: React.FC = () => {
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
            {t_i18n('TTP Network Graph')}
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
            {t_i18n('Shows relationships between TTPs used by hacktivists in attacks against the country')}
          </Typography>

          {/* Detail Panel + Graph */}
          <Box sx={{ display: 'flex', gap: 0 }}>
            <DetailPanel />
            <NetworkGraphPlaceholder />
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
};

export default TTPNetworkGraphSection;
