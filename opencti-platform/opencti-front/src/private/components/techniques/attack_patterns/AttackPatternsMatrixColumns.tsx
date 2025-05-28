import React, { useEffect, useMemo, useState } from 'react';
import { Box, ListItemIcon, ListItemText, Menu, MenuItem, Typography } from '@mui/material';
import { AddCircleOutlineOutlined, InfoOutlined } from '@mui/icons-material';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { Link } from 'react-router-dom';
import { useTheme } from '@mui/material/styles';
import { AttackPatternsMatrixProps, attackPatternsMatrixQuery } from '@components/techniques/attack_patterns/AttackPatternsMatrix';
import { AttackPatternsMatrixColumns_data$data, AttackPatternsMatrixColumns_data$key } from './__generated__/AttackPatternsMatrixColumns_data.graphql';
import { AttackPatternsMatrixQuery } from './__generated__/AttackPatternsMatrixQuery.graphql';
import { computeLevel } from '../../../../utils/Number';
import { truncate } from '../../../../utils/String';
import { MESSAGING$ } from '../../../../relay/environment';
import { UserContext } from '../../../../utils/hooks/useAuth';
import type { Theme } from '../../../../components/Theme';
import { hexToRGB } from '../../../../utils/Colors';

type AttackPattern = NonNullable<NonNullable<NonNullable<AttackPatternsMatrixColumns_data$data['attackPatternsMatrix']>['attackPatternsOfPhases']>[number]['attackPatterns']>[number];

type AttackPatternElement = AttackPattern & {
  id: AttackPattern['attack_pattern_id'],
  entity_type: string,
  level: number
};

interface AttackPatternsMatrixColumnsProps extends AttackPatternsMatrixProps {
  handleToggleModeOnlyActive?: () => void;
  currentModeOnlyActive?: boolean;
  queryRef: PreloadedQuery<AttackPatternsMatrixQuery>;
}

const LAYOUT_SIZE = {
  BASE_HEIGHT: 310,
  BASE_WIDTH: 110, // Base width when nav is closed
  NAV_WIDTH: 125, // Left nav width
  MARGIN_RIGHT_WIDTH: 195, // Right nav width
};

const colors = (defaultColor = '#ffffff') => [
  [defaultColor, 'transparent', hexToRGB('#ffffff', 0.1)],
  ['#ffffff', hexToRGB('#ffffff', 0.2)],
  ['#fff59d', hexToRGB('#fff59d', 0.2)],
  ['#ffe082', hexToRGB('#ffe082', 0.2)],
  ['#ffb300', hexToRGB('#ffb300', 0.2)],
  ['#ffb74d', hexToRGB('#ffb74d', 0.2)],
  ['#fb8c00', hexToRGB('#fb8c00', 0.2)],
  ['#d95f00', hexToRGB('#d95f00', 0.2)],
  ['#e64a19', hexToRGB('#e64a19', 0.2)],
  ['#f44336', hexToRGB('#f44336', 0.2)],
  ['#d32f2f', hexToRGB('#d32f2f', 0.2)],
  ['#b71c1c', hexToRGB('#b71c1c', 0.2)],
];

export const attackPatternsMatrixColumnsFragment = graphql`
  fragment AttackPatternsMatrixColumns_data on Query {
    attackPatternsMatrix {
      attackPatternsOfPhases {
        kill_chain_id
        kill_chain_name
        phase_name
        x_opencti_order
        attackPatterns {
          attack_pattern_id
          name
          description
          x_mitre_id
          subAttackPatternsIds
          subAttackPatternsSearchText
          killChainPhasesIds
        }
      }
    }
  }
`;

const AttackPatternsMatrixColumns = ({
  queryRef,
  attackPatterns,
  marginRight = false,
  searchTerm = '',
  handleAdd,
  selectedKillChain,
}: AttackPatternsMatrixColumnsProps) => {
  const theme = useTheme<Theme>();
  const [hover, setHover] = useState<Record<string, boolean>>({});
  const [anchorEl, setAnchorEl] = useState<EventTarget & Element | null>(null);
  const [selectedAttackPattern, setSelectedAttackPattern] = useState<AttackPatternElement | null>(null);
  const [navOpen, setNavOpen] = useState(localStorage.getItem('navOpen') === 'true');

  const data = usePreloadedQuery<AttackPatternsMatrixQuery>(attackPatternsMatrixQuery, queryRef);
  const { attackPatternsMatrix } = useFragment<AttackPatternsMatrixColumns_data$key>(
    attackPatternsMatrixColumnsFragment,
    data,
  );

  const handleOpen = (element: AttackPatternElement, event: React.MouseEvent) => {
    setAnchorEl(event.currentTarget);
    setSelectedAttackPattern(element);
  };

  const handleClose = () => {
    setAnchorEl(null);
    setSelectedAttackPattern(null);
  };

  const handleAddAttackPattern = (element: AttackPatternElement) => {
    const { id, name, entity_type } = element;

    handleAdd({ id, entity_type, name });
    handleClose();
  };

  const handleToggleHover = (id: string) => {
    setHover((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  useEffect(() => {
    const subscription = MESSAGING$.toggleNav.subscribe({
      next: () => setNavOpen(localStorage.getItem('navOpen') === 'true'),
    });
    return () => subscription.unsubscribe();
  }, []);

  const getLevel = (ap: AttackPattern): number => {
    const matchCount = attackPatterns.filter((n) => n.id === ap.attack_pattern_id || (ap.subAttackPatternsIds?.includes(n.id))).length;
    const maxCount = Math.max(...attackPatterns.map((n) => {
      const all = [n, ...(n.parentAttackPatterns?.edges || []).map((e) => e.node)];
      return all.length;
    }));
    return computeLevel(matchCount, 0, maxCount, 0, 10);
  };

  const filteredData = useMemo(() => attackPatternsMatrix?.attackPatternsOfPhases
    ?.filter((a) => a.kill_chain_name === selectedKillChain)
    .sort((a, b) => a.x_opencti_order - b.x_opencti_order)
    .map((a) => ({
      ...a,
      attackPatterns: a.attackPatterns
        ?.filter((ap) => !searchTerm
        || ap.name.toLowerCase().includes(searchTerm.toLowerCase())
        || ap.description?.toLowerCase().includes(searchTerm.toLowerCase())
        || ap.x_mitre_id?.toLowerCase().includes(searchTerm.toLowerCase())
        || ap.subAttackPatternsSearchText?.toLowerCase().includes(searchTerm.toLowerCase()))
        .map((ap) => ({
          ...ap,
          id: ap.attack_pattern_id,
          entity_type: 'Attack-Pattern',
          level: getLevel(ap),
        }))
        .sort((f, s) => f.name.localeCompare(s.name)),
    })), [attackPatternsMatrix, searchTerm, attackPatterns]);

  const matrixWidth = useMemo(() => {
    const baseOffset = LAYOUT_SIZE.BASE_WIDTH + (navOpen ? LAYOUT_SIZE.NAV_WIDTH : 0);
    const rightOffset = marginRight ? LAYOUT_SIZE.MARGIN_RIGHT_WIDTH : 0;
    return baseOffset + rightOffset;
  }, [marginRight, navOpen]);

  return (
    <UserContext.Consumer>
      {({ bannerSettings }) => {
        const matrixHeight = LAYOUT_SIZE.BASE_HEIGHT + (bannerSettings?.bannerHeightNumber || 0) * 2;

        return (
          <Box
            sx={{
              display: 'flex',
              flexDirection: 'column',
              width: `calc(100vw - ${matrixWidth}px)`,
              height: `calc(100vh - ${matrixHeight}px)`,
              overflowX: 'auto',
              whiteSpace: 'nowrap',
              paddingBottom: 2,
              position: 'relative',
              marginBlockStart: 3,
            }}
          >
            <Box display="flex">
              {filteredData?.map((col) => (
                <Box key={col.kill_chain_id} sx={{ mr: 1.5 }}>
                  <Box sx={{ textAlign: 'center', mb: 1 }}>
                    <Typography sx={{ fontSize: 15, fontWeight: 600 }}>{truncate(col.phase_name, 18)}</Typography>
                    <Typography variant="caption">{`${col.attackPatterns?.length} techniques`}</Typography>
                  </Box>
                  {col.attackPatterns?.map((ap) => {
                    const isHovered = hover[ap.id];
                    const level = isHovered && ap.level !== 0 ? ap.level - 1 : ap.level;
                    const position = isHovered && level === 0 ? 2 : 1;

                    const colorArray = colors(theme.palette.background.accent);
                    return (
                      <Box
                        key={ap.id}
                        onMouseEnter={() => handleToggleHover(ap.id)}
                        onMouseLeave={() => handleToggleHover(ap.id)}
                        onClick={(e) => handleOpen(ap, e)}
                        sx={{
                          cursor: 'pointer',
                          border: `1px solid ${colorArray[level][0]}`,
                          backgroundColor: colorArray[level][position],
                          padding: 1.25,
                        }}
                      >
                        <Typography variant="body2" fontSize={10}>
                          {ap.name}
                        </Typography>
                      </Box>
                    );
                  })}
                </Box>
              ))}
            </Box>

            <Menu anchorEl={anchorEl} open={!!anchorEl} onClose={handleClose}>
              {selectedAttackPattern && (
                <>
                  <MenuItem
                    component={Link}
                    to={`/dashboard/techniques/attack_patterns/${selectedAttackPattern?.id}`}
                    target="_blank"
                  >
                    <ListItemIcon><InfoOutlined fontSize="small"/></ListItemIcon>
                    <ListItemText>View</ListItemText>
                  </MenuItem>
                  <MenuItem onClick={() => handleAddAttackPattern(selectedAttackPattern)}>
                    <ListItemIcon><AddCircleOutlineOutlined fontSize="small"/></ListItemIcon>
                    <ListItemText>Add</ListItemText>
                  </MenuItem>
                </>
              )}
            </Menu>
          </Box>
        );
      }}
    </UserContext.Consumer>
  );
};

export default AttackPatternsMatrixColumns;
