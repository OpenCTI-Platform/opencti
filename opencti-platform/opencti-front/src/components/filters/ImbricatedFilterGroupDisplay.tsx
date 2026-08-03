import React, { CSSProperties, Fragment, FunctionComponent, ReactNode, useState } from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import { InformationOutline } from 'mdi-material-ui';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import Box from '@mui/material/Box';
import Tooltip from '@mui/material/Tooltip';
import { useTheme } from '@mui/material';
import type { Theme } from '@mui/material/styles/createTheme';
import CodeBlock from '@components/common/CodeBlock';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../i18n';
import { FilterRepresentative } from './FiltersModel';
import type { Filter, FilterGroup } from '../../utils/filters/filtersHelpers-types';
import FilterGroupsVisualDisplay from './FilterGroupsVisualDisplay';
import { convertOperatorToIcon, filterOperatorsWithIcon } from '../../utils/filters/filtersUtils';
import { truncate } from '../../utils/String';

// How many levels of nested groups are rendered inline before collapsing to "(…)".
const MAX_INLINE_DEPTH = 1;

interface ImbricatedFilterGroupDisplayProps {
  filterObj: FilterGroup;
  filterMode: string;
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  filterStyle?: CSSProperties;
}

const ImbricatedFilterGroupDisplay: FunctionComponent<ImbricatedFilterGroupDisplayProps> = ({
  filterObj,
  filterMode,
  filtersRepresentativesMap,
  filterStyle,
}) => {
  const { filterGroups } = filterObj;
  const [open, setOpen] = useState(false);
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const handleClickOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);

  // ── inline compact rendering ──────────────────────────────────────
  const modeBadge = (mode: string, key: string) => (
    <Box
      key={key}
      component="span"
      sx={{
        textTransform: 'uppercase',
        fontFamily: 'Consolas, monaco, monospace',
        fontWeight: 700,
        fontSize: '0.65rem',
        letterSpacing: '0.06em',
        padding: '2px 6px',
        borderRadius: '6px',
        backgroundColor: theme.palette.action.selected,
        color: theme.palette.text.secondary,
      }}
    >
      {t_i18n(mode)}
    </Box>
  );

  const compactChip = (filter: Filter, key: string) => {
    const filterLabel = t_i18n(filter.key);
    const operator = filter.operator ?? 'eq';
    const isOperatorIcon = filterOperatorsWithIcon.includes(operator);
    const valuesLabel = filter.values.length > 0
      ? filter.values.map((v) => filtersRepresentativesMap.get(v)?.value ?? v).join(filter.mode === 'and' ? ' & ' : ' | ')
      : '';
    return (
      <Box
        key={key}
        component="span"
        sx={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '4px',
          padding: '1px 8px',
          borderRadius: '6px',
          backgroundColor: theme.palette.background.default,
          border: `1px solid ${theme.palette.divider}`,
          maxWidth: 240,
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        <strong>{truncate(filterLabel, 20)}</strong>
        {isOperatorIcon
          ? convertOperatorToIcon(operator)
          : <span style={{ opacity: 0.7 }}>{t_i18n(operator)}</span>}
        {valuesLabel && <span>{truncate(valuesLabel, 30)}</span>}
      </Box>
    );
  };

  // Renders a group as: ( member <mode> member <mode> … )
  const compactGroup = (group: FilterGroup, depth: number, keyPrefix: string): ReactNode => {
    const members: ReactNode[] = [
      ...group.filters.map((f, i) => compactChip(f, `${keyPrefix}-f${i}`)),
      ...group.filterGroups.map((g, i) => (depth < MAX_INLINE_DEPTH
        ? compactGroup(g, depth + 1, `${keyPrefix}-g${i}`)
        : (
            <Box
              key={`${keyPrefix}-g${i}`}
              component="span"
              sx={{ fontFamily: 'Consolas, monaco, monospace', opacity: 0.7, padding: '0 4px' }}
            >
              (…)
            </Box>
          ))),
    ];
    return (
      <Box
        key={keyPrefix}
        component="span"
        sx={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          padding: '2px 8px',
          borderRadius: '8px',
          border: `1px solid ${theme.palette.warning.main}`,
          backgroundColor: 'rgba(255, 167, 38, 0.08)',
        }}
      >
        <Box component="span" sx={{ color: theme.palette.warning.main, fontWeight: 700, opacity: 0.8 }}>(</Box>
        {members.map((node, i) => (
          <Fragment key={`${keyPrefix}-m${i}`}>
            {i > 0 && modeBadge(group.mode, `${keyPrefix}-mode${i}`)}
            {node}
          </Fragment>
        ))}
        <Box component="span" sx={{ color: theme.palette.warning.main, fontWeight: 700, opacity: 0.8 }}>)</Box>
      </Box>
    );
  };

  return (
    <>
      <Tooltip title={t_i18n('Click to view or edit these nested groups in the Advanced filter builder')}>
        <Box
          onClick={handleClickOpen}
          sx={{
            ...(filterStyle as object),
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            cursor: 'pointer',
            flexWrap: 'wrap',
          }}
        >
          {filterGroups.map((group, i) => (
            <Fragment key={`inline-group-${i}`}>
              {(i > 0 || filterObj.filters.length > 0) && modeBadge(filterMode, `inline-mode-${i}`)}
              {compactGroup(group, 0, `inline-group-${i}`)}
            </Fragment>
          ))}
          <InformationOutline fontSize="small" color="warning" />
        </Box>
      </Tooltip>

      <Dialog
        open={open}
        onClose={handleClose}
        aria-labelledby="filter-groups-dialog-title"
        aria-describedby="Show Filter groups configuration"
      >
        <DialogTitle id="filter-groups-dialog-title">
          {t_i18n('Imbricated filter groups')}
        </DialogTitle>
        <DialogContent>
          <Typography
            variant="body2"
            sx={{ marginBottom: theme.spacing(2) }}
          >
            {t_i18n('This filter contains imbricated filter groups. They can be edited from the "Advanced" filter builder, or via the API. For your information, here is information about the content of the filter object.')}
          </Typography>
          <Typography
            variant="h3"
            sx={{ textTransform: 'none' }}
            gutterBottom
          >
            {t_i18n('Filter group content:')}
          </Typography>
          <FilterGroupsVisualDisplay
            filtersRepresentativesMap={filtersRepresentativesMap}
            filterGroups={filterGroups}
            filterMode={filterMode}
          />
          <Typography
            variant="h3"
            sx={{ textTransform: 'none' }}
            gutterBottom
          >
            {t_i18n('The complete Filter object is as follows:')}
          </Typography>
          <CodeBlock
            code={JSON.stringify(filterObj, null, 2)}
            language="json"
          />
        </DialogContent>
        <DialogActions sx={{ mr: 2, mb: 2 }}>
          <Button onClick={handleClose} autoFocus>
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ImbricatedFilterGroupDisplay;
