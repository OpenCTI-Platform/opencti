import React, { useState } from 'react';
import { Box, Typography, IconButton, Dialog, DialogTitle, DialogContent, DialogContentText, DialogActions, Button } from '@mui/material';
import { Clear } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import { graphql } from 'react-relay';
import AttackPatternsMatrixShouldCoverIcon from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixShouldCoverIcon';
import {
  FilteredAttackPattern,
  FilteredSubAttackPattern,
  getBoxStyles,
  MinimalAttackPattern,
} from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixColumns';
import type { Theme } from '../../../../../components/Theme';
import { commitMutation } from '../../../../../relay/environment';
import { useFormatter } from '../../../../../components/i18n';
import { hexToRGB } from '../../../../../utils/Colors';
import SecurityCoverageInformation from '../../../analyses/security_coverages/SecurityCoverageInformation';

interface AttackPatternsMatrixColumnsElementProps {
  attackPattern: FilteredAttackPattern | FilteredSubAttackPattern;
  handleOpen: (element: MinimalAttackPattern, event: React.MouseEvent) => void;
  attackPatternIdsToOverlap?: string[];
  isSecurityPlatform: boolean;
  isCoverage?: boolean;
  coverageMap?: Map<string, ReadonlyArray<{ readonly coverage_name: string; readonly coverage_score: number; }>>;
  entityId?: string;
}

const removeMutation = graphql`
  mutation AttackPatternsMatrixColumsElementRelationDeleteMutation(
    $fromId: StixRef!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixCoreRelationshipDelete(
      fromId: $fromId
      toId: $toId
      relationship_type: $relationship_type
    )
  }
`;

const AttackPatternsMatrixColumnsElement = ({
  attackPattern,
  handleOpen,
  attackPatternIdsToOverlap,
  isSecurityPlatform,
  isCoverage = false,
  coverageMap,
  entityId,
}: AttackPatternsMatrixColumnsElementProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [isHovered, setIsHovered] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(false);

  const handleDelete = () => {
    if (!entityId || !attackPattern.attack_pattern_id) return;
    commitMutation({
      mutation: removeMutation,
      variables: {
        fromId: entityId,
        toId: attackPattern.attack_pattern_id,
        relationship_type: 'has-covered',
      },
      updater: (store: any) => {
        // Remove the relationship from the store
        const payload = store.getRootField('stixCoreRelationshipDelete');
        if (!payload) return;

        // Get the deleted relationship ID
        const deletedId = payload.getValue('id');
        if (!deletedId) return;

        // Delete the record from the store
        store.delete(deletedId);
      },
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onCompleted: () => {
        setDisplayDelete(false);
      },
      onError: undefined,
      setSubmitting: undefined,
    });
  };

  // Get coverage information if in coverage mode
  const coverage = isCoverage && coverageMap ? coverageMap.get(attackPattern.attack_pattern_id) : null;

  // Calculate colors based on coverage score for active/covered boxes
  const getCoverageColors = () => {
    if (!isCoverage || !attackPattern.isCovered) {
      // Use default box styles when not in coverage mode or not covered
      const defaultStyles = getBoxStyles({ attackPattern, isHovered, isSecurityPlatform, theme });
      return { backgroundColor: defaultStyles.backgroundColor, border: defaultStyles.border };
    }

    // Box is covered and we're in coverage mode
    if (!coverage || coverage.length === 0) {
      // No coverage data but box is covered - use blue for unknown
      const bgColor = isHovered
        ? hexToRGB(theme.palette.primary.main, 0.3)
        : hexToRGB(theme.palette.primary.main, 0.15);
      const borderColor = hexToRGB(theme.palette.primary.main, 0.5);
      return {
        backgroundColor: bgColor,
        border: `1px solid ${borderColor}`,
      };
    }

    // Get the average coverage score if there are multiple coverages
    const avgScore = coverage.reduce((sum, c) => sum + c.coverage_score, 0) / coverage.length;

    // Calculate color based on score (0-100)
    // Green to red gradient
    const red = Math.round(255 * (1 - avgScore / 100));
    const green = Math.round(255 * (avgScore / 100));
    const bgOpacity = isHovered ? 0.25 : 0.15;
    const borderOpacity = 0.5;

    return {
      backgroundColor: `rgba(${red}, ${green}, 0, ${bgOpacity})`,
      border: `1px solid rgba(${red}, ${green}, 0, ${borderOpacity})`,
    };
  };

  // Get styles based on coverage mode
  const styles = isCoverage
    ? getCoverageColors()
    : getBoxStyles({ attackPattern, isHovered, isSecurityPlatform, theme });
  const { border, backgroundColor } = styles;
  return (
    <Box
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      onClick={(e) => handleOpen(attackPattern, e)}
      sx={{
        display: 'flex',
        cursor: 'pointer',
        border,
        backgroundColor,
        padding: 1.25,
        justifyContent: 'space-between',
        gap: 1,
        alignItems: 'center',
        whiteSpace: 'normal',
        width: '100%',
        position: 'relative',
      }}
    >
      <Typography variant="body2" fontSize={10}>
        {attackPattern.name}
      </Typography>

      {isCoverage && attackPattern.isCovered && (
        <>
          <Box sx={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <SecurityCoverageInformation
              coverage_information={coverage || null}
              variant="matrix"
            />
          </Box>
          {entityId && (
            <>
              <IconButton
                size="small"
                onClick={(e) => {
                  e.stopPropagation();
                  e.preventDefault();
                  setDisplayDelete(true);
                }}
                sx={{
                  position: 'absolute',
                  top: 2,
                  right: 2,
                  padding: '2px',
                  '& .MuiSvgIcon-root': { fontSize: 12 },
                }}
              >
                <Clear />
              </IconButton>
              <Dialog
                open={displayDelete}
                onClose={() => setDisplayDelete(false)}
                PaperProps={{ elevation: 1 }}
              >
                <DialogTitle>{t_i18n('Are you sure?')}</DialogTitle>
                <DialogContent>
                  <DialogContentText>
                    {t_i18n('Do you want to remove the coverage for this attack pattern?')}
                  </DialogContentText>
                </DialogContent>
                <DialogActions>
                  <Button onClick={() => setDisplayDelete(false)}>
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={handleDelete}
                  >
                    {t_i18n('Delete')}
                  </Button>
                </DialogActions>
              </Dialog>
            </>
          )}
        </>
      )}

      {!isSecurityPlatform && attackPatternIdsToOverlap?.length !== undefined && attackPattern.isCovered && !isCoverage && (
        <AttackPatternsMatrixShouldCoverIcon
          isOverlapping={attackPattern.isOverlapping || false}
        />
      )}
    </Box>
  );
};

export default AttackPatternsMatrixColumnsElement;
