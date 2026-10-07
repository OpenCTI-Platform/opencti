import React from 'react';
import { Link } from 'react-router';
import { Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { Box } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { resolveLink } from '../../../../utils/Entity';
import { formatSimilarityScore } from './graphAnalyticsUtils';

export interface MatrixEntity {
  readonly id: string;
  readonly entity_type: string;
  readonly representative: { readonly main: string };
}

export interface MatrixCell {
  readonly source_id: string;
  readonly target_id: string;
  readonly score: number;
  readonly shared_count: number;
}

interface GraphSimilarityMatrixProps {
  entities: ReadonlyArray<MatrixEntity>;
  cells: ReadonlyArray<MatrixCell>;
  // public dashboards have no access to the entity pages
  disableLinks?: boolean;
}

const LABEL_WIDTH = 180;
const CELL_SIZE = 44;

/** Pairwise similarity heat map: the stronger the color, the more the two entities share. */
const GraphSimilarityMatrix = ({ entities, cells, disableLinks = false }: GraphSimilarityMatrixProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  if (entities.length < 2) {
    return <Text variant="content-compact">{t_i18n('Select at least two entities to compare them')}</Text>;
  }
  const byPair = new Map(cells.map((cell) => [`${cell.source_id}|${cell.target_id}`, cell]));
  // color-mix keeps working when the palette color is a CSS variable
  const cellColor = (score: number) => `color-mix(in srgb, ${theme.palette.primary.main} ${Math.round(score * 100)}%, transparent)`;
  return (
    <Box sx={{ overflow: 'auto', maxWidth: '100%' }} data-testid="graph-similarity-matrix">
      <table style={{ borderCollapse: 'separate', borderSpacing: 2 }}>
        <thead>
          <tr>
            <th style={{ width: LABEL_WIDTH }} aria-label={t_i18n('Entity')} />
            {entities.map((entity) => (
              <th key={entity.id} style={{ width: CELL_SIZE, height: LABEL_WIDTH, verticalAlign: 'bottom' }}>
                <Box sx={{ typography: 'caption', writingMode: 'vertical-rl', transform: 'rotate(180deg)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxHeight: LABEL_WIDTH }}>
                  {entity.representative.main}
                </Box>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {entities.map((row) => (
            <tr key={row.id}>
              <Box component="th" scope="row" sx={{ textAlign: 'left', fontWeight: 'fontWeightRegular' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: LABEL_WIDTH }}>
                  <ItemIcon type={row.entity_type} size="small" />
                  {disableLinks ? (
                    <Box component="span" sx={{ typography: 'caption', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {row.representative.main}
                    </Box>
                  ) : (
                    <Box
                      component={Link}
                      to={`${resolveLink(row.entity_type)}/${row.id}`}
                      sx={{ typography: 'caption', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                    >
                      {row.representative.main}
                    </Box>
                  )}
                </Box>
              </Box>
              {entities.map((column) => {
                if (row.id === column.id) {
                  return <td key={column.id} style={{ width: CELL_SIZE, height: CELL_SIZE, background: theme.palette.divider }} />;
                }
                const cell = byPair.get(`${row.id}|${column.id}`);
                const score = cell?.score ?? 0;
                const description = t_i18n('{source} and {target}: {score} similar, {count, plural, one {# shared element} other {# shared elements}}', {
                  values: { source: row.representative.main, target: column.representative.main, score: formatSimilarityScore(score), count: cell?.shared_count ?? 0 },
                });
                return (
                  <td key={column.id} style={{ width: CELL_SIZE, height: CELL_SIZE, padding: 0 }}>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Box
                          tabIndex={0}
                          aria-label={description}
                          sx={{
                            typography: 'caption',
                            width: CELL_SIZE,
                            height: CELL_SIZE,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            borderRadius: 1,
                            background: cellColor(score),
                            border: `1px solid ${theme.palette.divider}`,
                          }}
                        >
                          {score > 0 ? Math.round(score * 100) : ''}
                        </Box>
                      </TooltipTrigger>
                      <TooltipContent>{description}</TooltipContent>
                    </Tooltip>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </Box>
  );
};

export default GraphSimilarityMatrix;
