import React, { useEffect, useMemo, useState } from 'react';
import { Box, ListItemIcon, ListItemText, Menu, MenuItem, Typography } from '@mui/material';
import { AddCircleOutlineOutlined, InfoOutlined } from '@mui/icons-material';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { Link } from 'react-router-dom';
import { useTheme } from '@mui/material/styles';
import { AttackPatternsMatrixProps } from '@components/techniques/attack_patterns/AttackPatternsMatrix';
import { AttackPatternsMatrixColumns_data$data, AttackPatternsMatrixColumns_data$key } from './__generated__/AttackPatternsMatrixColumns_data.graphql';
import { AttackPatternsMatrixColumnsQuery } from './__generated__/AttackPatternsMatrixColumnsQuery.graphql';
import AttackPatternsMatrixBar from './AttackPatternsMatrixBar';
import { computeLevel } from '../../../../utils/Number';
import { truncate } from '../../../../utils/String';
import { MESSAGING$ } from '../../../../relay/environment';
import { UserContext } from '../../../../utils/hooks/useAuth';
import type { Theme } from '../../../../components/Theme';

type AttackPattern = NonNullable<NonNullable<NonNullable<AttackPatternsMatrixColumns_data$data['attackPatternsMatrix']>['attackPatternsOfPhases']>[number]['attackPatterns']>[number];

type AttackPatternElement = AttackPattern & {
  id: AttackPattern['attack_pattern_id'],
  entity_type: string,
  level: number
};

interface AttackPatternsMatrixColumnsProps extends AttackPatternsMatrixProps {
  handleToggleModeOnlyActive?: () => void;
  currentModeOnlyActive?: boolean;
  queryRef: PreloadedQuery<AttackPatternsMatrixColumnsQuery>;
}

const colors = (defaultColor = '#ffffff') => [
  [defaultColor, 'transparent', 'rgba(255,255,255,0.1)'],
  ['#ffffff', 'rgba(255,255,255,0.2)'],
  ['#fff59d', 'rgba(255,245,157,0.2)'],
  ['#ffe082', 'rgba(255,224,130,0.2)'],
  ['#ffb300', 'rgba(255,179,0,0.2)'],
  ['#ffb74d', 'rgba(255,183,77,0.2)'],
  ['#fb8c00', 'rgba(251,140,0,0.2)'],
  ['#d95f00', 'rgba(217,95,0,0.2)'],
  ['#e64a19', 'rgba(230,74,25,0.2)'],
  ['#f44336', 'rgba(244,67,54,0.2)'],
  ['#d32f2f', 'rgba(211,47,47,0.2)'],
  ['#b71c1c', 'rgba(183,28,28,0.2)'],
];

export const attackPatternsMatrixColumnsQuery = graphql`
  query AttackPatternsMatrixColumnsQuery {
    ...AttackPatternsMatrixColumns_data
  }
`;

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
  handleToggleModeOnlyActive,
  currentModeOnlyActive,
  handleAdd,
  selectedKillChain,
  noBottomBar = false,
}: AttackPatternsMatrixColumnsProps) => {
  const theme = useTheme<Theme>();
  const [hover, setHover] = useState<Record<string, boolean>>({});
  const [anchorEl, setAnchorEl] = useState<EventTarget & Element | null>(null);
  const [selectedAttackPattern, setSelectedAttackPattern] = useState<AttackPatternElement | null>(null);
  const [navOpen, setNavOpen] = useState(localStorage.getItem('navOpen') === 'true');
  const [modeOnlyActive, setModeOnlyActive] = useState(currentModeOnlyActive ?? false);
  const [currentKillChain, setCurrentKillChain] = useState(selectedKillChain);

  const data = usePreloadedQuery<AttackPatternsMatrixColumnsQuery>(attackPatternsMatrixColumnsQuery, queryRef);
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

  const toggleMode = () => handleToggleModeOnlyActive || setModeOnlyActive((prev) => !prev);
  const onKillChainChange = (e: React.ChangeEvent<{ value: string }>) => {
    setCurrentKillChain(e.target.value);
  };

  useEffect(() => {
    const subscription = MESSAGING$.toggleNav.subscribe({
      next: () => setNavOpen(localStorage.getItem('navOpen') === 'true'),
    });
    return () => subscription.unsubscribe();
  }, []);

  // Get deduplicated & sorted kill chains
  const killChains = useMemo(
    () => Array.from(
      new Set(
        attackPatternsMatrix?.attackPatternsOfPhases
          ?.map((a) => a.kill_chain_name),
      ),
    ).sort((a, b) => a.localeCompare(b)),
    [attackPatternsMatrix],
  );

  // Handle kill chain changes
  useEffect(() => {
    if (killChains.length > 0) {
      const initialKillChain = selectedKillChain && killChains.includes(selectedKillChain)
        ? selectedKillChain
        : killChains[0];
      setCurrentKillChain(initialKillChain);
    }
  }, [killChains, selectedKillChain]);

  const getLevel = (ap: AttackPattern): number => {
    const matchCount = attackPatterns.filter((n) => n.id === ap.attack_pattern_id || (ap.subAttackPatternsIds?.includes(n.id))).length;
    const maxCount = Math.max(...attackPatterns.map((n) => {
      const all = [n, ...(n.parentAttackPatterns?.edges || []).map((e) => e.node)];
      return all.length;
    }));
    return computeLevel(matchCount, 0, maxCount, 0, 10);
  };

  const filteredData = useMemo(() => attackPatternsMatrix?.attackPatternsOfPhases
    ?.filter((a) => a.kill_chain_name === currentKillChain)
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
        .filter((o) => (modeOnlyActive ? o.level > 0 : o.level >= 0))
        .sort((f, s) => f.name.localeCompare(s.name)),
    })), [attackPatternsMatrix, currentKillChain, searchTerm, modeOnlyActive, attackPatterns]);

  const matrixWidth = useMemo(() => {
    if (marginRight) {
      return navOpen ? 'calc(100vw - 430px)' : 'calc(100vw - 305px)';
    }
    return navOpen ? 'calc(100vw - 235px)' : 'calc(100vw - 110px)';
  }, [marginRight, navOpen]);

  return (
    <UserContext.Consumer>
      {({ bannerSettings }) => {
        const matrixHeight = 310 + (bannerSettings?.bannerHeightNumber || 0) * 2;

        return (
          <Box
            sx={{
              width: matrixWidth,
              minWidth: matrixWidth,
              maxWidth: matrixWidth,
              height: `calc(100vh - ${matrixHeight}px)`,
              minHeight: `calc(100vh - ${matrixHeight}px)`,
              maxHeight: `calc(100vh - ${matrixHeight}px)`,
              overflowX: 'auto',
              whiteSpace: 'nowrap',
              paddingBottom: 2,
              position: 'relative',
              marginBlockStart: 3,
            }}
          >
            {!noBottomBar && (
              <AttackPatternsMatrixBar
                currentModeOnlyActive={modeOnlyActive}
                handleToggleModeOnlyActive={toggleMode}
                currentKillChain={currentKillChain}
                handleChangeKillChain={onKillChainChange}
                killChains={killChains}
                navOpen={navOpen}
              />
            )}
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
