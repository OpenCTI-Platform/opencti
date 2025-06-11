import React, { useEffect, useMemo, useState } from 'react';
import { Box, ListItemIcon, ListItemText, Menu, MenuItem, Typography } from '@mui/material';
import { AddCircleOutlineOutlined, InfoOutlined } from '@mui/icons-material';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { Link } from 'react-router-dom';
import { useTheme } from '@mui/material/styles';
import { AttackPatternsMatrixProps, attackPatternsMatrixQuery } from '@components/techniques/attack_patterns/AttackPatternsMatrix/AttackPatternsMatrix';
import AccordionAttackPattern from '@components/techniques/attack_patterns/AttackPatternsMatrix/AttackPatternsMatrixAccordion';
import AttackPatternsMatrixBadge from '@components/techniques/attack_patterns/AttackPatternsMatrix/AttackPatternsMatrixBadge';
import AttackPatternsMatrixColumnsElement from '@components/techniques/attack_patterns/AttackPatternsMatrix/AttackPatternsMatrixColumsElement';
import { AttackPatternsMatrixColumns_data$data, AttackPatternsMatrixColumns_data$key } from '../__generated__/AttackPatternsMatrixColumns_data.graphql';
import { AttackPatternsMatrixQuery } from '../__generated__/AttackPatternsMatrixQuery.graphql';
import { truncate } from '../../../../../utils/String';
import { MESSAGING$ } from '../../../../../relay/environment';
import { UserContext } from '../../../../../utils/hooks/useAuth';
import { hexToRGB } from '../../../../../utils/Colors';
import useHelper from '../../../../../utils/hooks/useHelper';
import type { Theme } from '../../../../../components/Theme';

export type AttackPattern = NonNullable<NonNullable<NonNullable<AttackPatternsMatrixColumns_data$data['attackPatternsMatrix']>['attackPatternsOfPhases']>[number]['attackPatterns']>[number];
export type SubAttackPattern = NonNullable<AttackPattern['subAttackPatterns']>[number];
export type MinimalAttackPattern = {
  attack_pattern_id: string;
  name: string;
};
export type FilteredSubAttackPattern = SubAttackPattern & {
  level: number;
  isOverlapping?: boolean;
  subAttackPatternsTotal?: number;
};

export type FilteredAttackPattern = AttackPattern & {
  level: number;
  isOverlapping?: boolean;
  subAttackPatternsTotal?: number;
  subAttackPatterns: FilteredSubAttackPattern[] | undefined;
};

type FilteredData = {
  readonly kill_chain_id: string;
  readonly kill_chain_name: string;
  readonly x_opencti_order: number;
  attackPatterns: FilteredAttackPattern[] | undefined;
  readonly phase_name: string;
};

interface AttackPatternsMatrixColumnsProps extends AttackPatternsMatrixProps {
  queryRef: PreloadedQuery<AttackPatternsMatrixQuery>;
}

const LAYOUT_SIZE = {
  BASE_HEIGHT: 310,
  BASE_WIDTH: 110, // Base width when nav is closed
  NAV_WIDTH: 125, // Left nav width
  MARGIN_RIGHT_WIDTH: 195, // Right nav width
};

const COLORS = {
  DEFAULT_BG: 'transparent',
  DEFAULT_BG_HOVER: '#ffffff',
  HIGHLIGHT: '#b71c1c',
  HIGHLIGHT_HOVER: '#d32f2f',
  BADGE: '#fa5e5e',
};

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
          subAttackPatterns {
            attack_pattern_id
            name
            description
          }
          subAttackPatternsSearchText
          killChainPhasesIds
        }
      }
    }
  }
`;

export const getBoxStyles = (hasLevel: boolean, isHovered: boolean, theme: Theme) => {
  if (hasLevel) {
    const highlightedColor = isHovered ? COLORS.HIGHLIGHT_HOVER : COLORS.HIGHLIGHT;
    return {
      border: `1px solid ${highlightedColor}`,
      backgroundColor: hexToRGB(highlightedColor, 0.2),
    };
  }
  return {
    border: `1px solid ${theme.palette.background.accent}`,
    backgroundColor: isHovered
      ? hexToRGB(COLORS.DEFAULT_BG_HOVER, 0.1)
      : COLORS.DEFAULT_BG,
  };
};

const AttackPatternsMatrixColumns = ({
  queryRef,
  attackPatterns,
  attackPatternIdsToOverlap,
  marginRight = false,
  searchTerm = '',
  handleAdd,
  selectedKillChain,
  isModeOnlyActive,
}: AttackPatternsMatrixColumnsProps) => {
  const theme = useTheme<Theme>();
  const { isFeatureEnable } = useHelper();
  const isSecurityPlatformEnabled = isFeatureEnable('SECURITY_PLATFORM');
  const [hover, setHover] = useState<Record<string, boolean>>({});
  const [anchorEl, setAnchorEl] = useState<EventTarget & Element | null>(null);
  const [selectedAttackPattern, setSelectedAttackPattern] = useState<MinimalAttackPattern | null>(null);
  const [navOpen, setNavOpen] = useState(localStorage.getItem('navOpen') === 'true');

  const data = usePreloadedQuery<AttackPatternsMatrixQuery>(attackPatternsMatrixQuery, queryRef);
  const { attackPatternsMatrix } = useFragment<AttackPatternsMatrixColumns_data$key>(
    attackPatternsMatrixColumnsFragment,
    data,
  );

  const handleOpen = (element: MinimalAttackPattern, event: React.MouseEvent) => {
    setAnchorEl(event.currentTarget);
    setSelectedAttackPattern(element);
  };

  const handleClose = () => {
    setAnchorEl(null);
    setSelectedAttackPattern(null);
  };

  const handleAddAttackPattern = (element: MinimalAttackPattern) => {
    const { attack_pattern_id: id, name } = element;
    handleAdd({ id, entity_type: 'Attack-Pattern', name });
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

  const getAttackPatternLevel = (ap: AttackPattern): number => {
    return attackPatterns.filter((n) => n.id === ap.attack_pattern_id || (ap.subAttackPatterns?.find((sub) => n.id === sub.attack_pattern_id))).length;
  };

  const getSubAttackPatternLevel = (sap: SubAttackPattern): number => {
    return attackPatterns.filter((n) => n.id === sap.attack_pattern_id).length;
  };

  const filteredData: FilteredData[] | undefined = useMemo(() => attackPatternsMatrix?.attackPatternsOfPhases
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
          level: getAttackPatternLevel(ap),
          subAttackPatterns: ap.subAttackPatterns?.map((sub) => ({
            ...sub,
            level: getSubAttackPatternLevel(sub),
            isOverlapping: attackPatternIdsToOverlap?.includes(sub.attack_pattern_id),
          })),
          isOverlapping: attackPatternIdsToOverlap?.includes(ap.attack_pattern_id),
          subAttackPatternsTotal: ap.subAttackPatterns?.length,
        }))
        .filter((o) => (isModeOnlyActive ? o.level > 0 : o.level >= 0))
        .sort((f, s) => f.name.localeCompare(s.name)),
    })), [attackPatternsMatrix, searchTerm, attackPatterns, attackPatternIdsToOverlap, isModeOnlyActive]);

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
                <Box key={col.kill_chain_id} sx={{ mr: 1.5, display: 'flex', flexDirection: 'column', minWidth: 150 }}>
                  <Box sx={{ textAlign: 'center', mb: 1, textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    <Typography sx={{ fontSize: 15, fontWeight: 600 }}>{truncate(col.phase_name, 18)}</Typography>
                    <Typography variant="caption">{`${col.attackPatterns?.length} techniques`}</Typography>
                  </Box>
                  {col.attackPatterns?.map((ap) => {
                    const isHovered = hover[ap.attack_pattern_id];
                    const hasLevel = ap.level > 0;
                    const { border, backgroundColor } = getBoxStyles(hasLevel, isHovered, theme);

                    return (
                      isSecurityPlatformEnabled && ap.subAttackPatterns?.length ? (
                        <AttackPatternsMatrixBadge
                          attackPattern={ap}
                          color={COLORS.BADGE}
                        >
                          <AccordionAttackPattern
                            attackPattern={ap}
                            handleToggleHover={handleToggleHover}
                            handleOpen={handleOpen}
                            hover={hover}
                            border={border}
                            backgroundColor={backgroundColor}
                            isSecurityPlatformEnabled={isSecurityPlatformEnabled}
                            attackPatternIdsToOverlap={attackPatternIdsToOverlap}
                          />
                        </AttackPatternsMatrixBadge>
                      ) : (
                        <AttackPatternsMatrixColumnsElement
                          attackPattern={ap}
                          handleToggleHover={handleToggleHover}
                          handleOpen={handleOpen}
                          border={border}
                          backgroundColor={backgroundColor}
                          attackPatternIdsToOverlap={attackPatternIdsToOverlap}
                        />
                      )
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
                    to={`/dashboard/techniques/attack_patterns/${selectedAttackPattern?.attack_pattern_id}`}
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
