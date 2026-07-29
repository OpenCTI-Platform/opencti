import { OPEN_BAR_WIDTH, SMALL_BAR_WIDTH } from '@components/nav/LeftBar';
import {
  CategoryOutlined,
  DescriptionOutlined,
  EventOutlined,
  HubOutlined,
  LayersClearOutlined,
  WarningAmberOutlined,
} from '@mui/icons-material';
import Badge from '@mui/material/Badge';
import Button from '@mui/material/Button';
import Checkbox from '@mui/material/Checkbox';
import Divider from '@mui/material/Divider';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import ListItemText from '@mui/material/ListItemText';
import ListSubheader from '@mui/material/ListSubheader';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Tooltip from '@mui/material/Tooltip';
import { useTheme } from '@mui/material/styles';
import { MouseEvent, ReactNode, useState } from 'react';
import ItemIcon from '../ItemIcon';
import type { Theme } from '../Theme';
import { useFormatter } from '../i18n';
import useAuth from '../../utils/hooks/useAuth';
import useDraftContext, { DRAFT_TOOLBAR_HEIGHT } from '../../utils/hooks/useDraftContext';
import {
  CORRELATION_CONTAINER_TYPES,
  CORRELATION_ENTITY_TYPES,
  CORRELATION_TARGET_TYPES,
  DateReference,
  OverCorrelatedObject,
  SourceTypeCount,
} from './correlationTimelineModel';

export const NO_LIMIT = 1000000;
export const TOOLBAR_HEIGHT = 54;

// A compact toolbar button owning its own menu, so that the toolbar itself
// stays a flat list of controls.
const ToolbarMenu = ({
  label,
  icon,
  active,
  children,
}: {
  label: string;
  icon: ReactNode;
  active: boolean;
  children: (close: () => void) => ReactNode;
}) => {
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const close = () => setAnchorEl(null);
  return (
    <>
      <Button
        size="small"
        color={active ? 'secondary' : 'inherit'}
        startIcon={icon}
        onClick={(event: MouseEvent<HTMLButtonElement>) => setAnchorEl(event.currentTarget)}
        sx={{ textTransform: 'none', whiteSpace: 'nowrap' }}
      >
        {label}
      </Button>
      <Menu
        anchorEl={anchorEl}
        open={!!anchorEl}
        onClose={close}
        anchorOrigin={{ vertical: 'top', horizontal: 'left' }}
        transformOrigin={{ vertical: 'bottom', horizontal: 'left' }}
      >
        {children(close)}
      </Menu>
    </>
  );
};

interface CorrelationTimelineToolbarProps {
  availableSourceTypes: SourceTypeCount[];
  sourceTypes: string[] | null;
  setSourceTypes: (value: string[] | null) => void;
  maxContainers: number;
  setMaxContainers: (value: number) => void;
  minShared: number;
  setMinShared: (value: number) => void;
  targetTypes: string[];
  setTargetTypes: (value: string[]) => void;
  dateReference: DateReference;
  setDateReference: (value: DateReference) => void;
  overCorrelated: OverCorrelatedObject[];
  sourcesCount: number;
  targetsCount: number;
}

const CorrelationTimelineToolbar = ({
  availableSourceTypes,
  sourceTypes,
  setSourceTypes,
  maxContainers,
  setMaxContainers,
  minShared,
  setMinShared,
  targetTypes,
  setTargetTypes,
  dateReference,
  setDateReference,
  overCorrelated,
  sourcesCount,
  targetsCount,
}: CorrelationTimelineToolbarProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();
  const draftContext = useDraftContext();
  const { bannerSettings: { bannerHeightNumber } } = useAuth();
  const navOpen = localStorage.getItem('navOpen') === 'true';

  const allTypes = availableSourceTypes.map((entry) => entry.type);
  const selectedTypes = sourceTypes ?? allTypes;
  const observableTypes = availableSourceTypes
    .filter((entry) => entry.isObservable)
    .map((entry) => entry.type);

  const toggleSourceType = (type: string) => {
    const next = selectedTypes.includes(type)
      ? selectedTypes.filter((current) => current !== type)
      : [...selectedTypes, type];
    setSourceTypes(next.length === allTypes.length ? null : next);
  };

  const toggleTargetType = (type: string) => {
    const next = targetTypes.includes(type)
      ? targetTypes.filter((current) => current !== type)
      : [...targetTypes, type];
    // Never let the selection reach zero: the chart would be empty with no
    // way of telling why.
    setTargetTypes(next.length > 0 ? next : CORRELATION_TARGET_TYPES);
  };

  const targetTypeItems = (group: string[]) => group.map((type) => (
    <MenuItem key={type} dense onClick={() => toggleTargetType(type)}>
      <Checkbox size="small" checked={targetTypes.includes(type)} />
      <ItemIcon type={type} size="small" />
      <ListItemText sx={{ marginLeft: 1 }} primary={t_i18n(type)} />
    </MenuItem>
  ));

  return (
    <Drawer
      anchor="bottom"
      variant="permanent"
      PaperProps={{
        elevation: 1,
        style: {
          zIndex: 1,
          paddingLeft: navOpen ? OPEN_BAR_WIDTH : SMALL_BAR_WIDTH,
          height: TOOLBAR_HEIGHT,
          overflow: 'hidden',
          marginBottom: bannerHeightNumber,
          bottom: draftContext ? DRAFT_TOOLBAR_HEIGHT : 0,
        },
      }}
    >
      <div
        className="hide-scrollbar"
        style={{
          height: TOOLBAR_HEIGHT,
          flex: '0 0 auto',
          display: 'flex',
          alignItems: 'center',
          gap: theme.spacing(0.5),
          padding: `0 ${theme.spacing(1)}`,
          overflowX: 'auto',
          overflowY: 'hidden',
        }}
      >
        <ToolbarMenu
          label={`${t_i18n('Correlate on')} · ${sourceTypes ? `${selectedTypes.length}/${allTypes.length}` : t_i18n('all')}`}
          icon={<CategoryOutlined fontSize="small" />}
          active={!!sourceTypes}
        >
          {(close) => [
            <ListSubheader key="header">{t_i18n('Entity types to correlate on')}</ListSubheader>,
            <MenuItem
              key="all"
              dense
              onClick={() => {
                setSourceTypes(null);
                close();
              }}
            >
              <ListItemText primary={t_i18n('All entity types')} />
            </MenuItem>,
            <MenuItem
              key="observables"
              dense
              disabled={observableTypes.length === 0}
              onClick={() => {
                setSourceTypes(observableTypes);
                close();
              }}
            >
              <ListItemText primary={t_i18n('Observables only')} />
            </MenuItem>,
            <Divider key="divider" />,
            ...availableSourceTypes.map(({ type, count }) => (
              <MenuItem key={type} dense onClick={() => toggleSourceType(type)}>
                <Checkbox size="small" checked={selectedTypes.includes(type)} />
                <ItemIcon type={type} size="small" />
                <ListItemText sx={{ marginLeft: 1 }} primary={`${t_i18n(type)} (${count})`} />
              </MenuItem>
            )),
          ]}
        </ToolbarMenu>

        <Divider sx={{ margin: 1, height: '60%' }} orientation="vertical" />

        <ToolbarMenu
          label={`${t_i18n('Over-correlation')} · ${maxContainers === NO_LIMIT ? t_i18n('off') : `>${maxContainers}`}`}
          icon={<LayersClearOutlined fontSize="small" />}
          active={maxContainers !== NO_LIMIT}
        >
          {(close) => [
            <ListSubheader key="header">{t_i18n('Hide objects present in more than')}</ListSubheader>,
            ...[5, 10, 20, 50, 100, NO_LIMIT].map((value) => (
              <MenuItem
                key={value}
                dense
                selected={maxContainers === value}
                onClick={() => {
                  setMaxContainers(value);
                  close();
                }}
              >
                <ListItemText
                  primary={value === NO_LIMIT ? t_i18n('No limit') : `${value} ${t_i18n('containers')}`}
                />
              </MenuItem>
            )),
          ]}
        </ToolbarMenu>

        <ToolbarMenu
          label={`${t_i18n('Shared')} · ≥${minShared}`}
          icon={<HubOutlined fontSize="small" />}
          active={minShared > 1}
        >
          {(close) => [
            <ListSubheader key="header">{t_i18n('Minimum shared objects')}</ListSubheader>,
            ...[1, 2, 3, 5].map((value) => (
              <MenuItem
                key={value}
                dense
                selected={minShared === value}
                onClick={() => {
                  setMinShared(value);
                  close();
                }}
              >
                <ListItemText primary={`≥ ${value}`} />
              </MenuItem>
            )),
          ]}
        </ToolbarMenu>

        <ToolbarMenu
          label={`${t_i18n('Correlate with')} · ${targetTypes.length}/${CORRELATION_TARGET_TYPES.length}`}
          icon={<DescriptionOutlined fontSize="small" />}
          active={targetTypes.length !== CORRELATION_TARGET_TYPES.length}
        >
          {() => [
            <ListSubheader key="containers-header">{t_i18n('Containers')}</ListSubheader>,
            ...targetTypeItems(CORRELATION_CONTAINER_TYPES),
            <Divider key="divider" />,
            <ListSubheader key="entities-header">{t_i18n('Entities')}</ListSubheader>,
            ...targetTypeItems(CORRELATION_ENTITY_TYPES),
          ]}
        </ToolbarMenu>

        <ToolbarMenu
          label={`${t_i18n('Date')} · ${dateReference === 'functional' ? t_i18n('functional') : t_i18n('technical')}`}
          icon={<EventOutlined fontSize="small" />}
          active={dateReference === 'technical'}
        >
          {(close) => [
            <ListSubheader key="header">{t_i18n('Date reference')}</ListSubheader>,
            <MenuItem
              key="functional"
              dense
              selected={dateReference === 'functional'}
              onClick={() => {
                setDateReference('functional');
                close();
              }}
            >
              <ListItemText
                primary={t_i18n('Functional date')}
                secondary={t_i18n('Publication for a report, first seen for a campaign or an incident')}
              />
            </MenuItem>,
            <MenuItem
              key="technical"
              dense
              selected={dateReference === 'technical'}
              onClick={() => {
                setDateReference('technical');
                close();
              }}
            >
              <ListItemText
                primary={t_i18n('Technical date')}
                secondary={t_i18n('When the object entered the platform')}
              />
            </MenuItem>,
          ]}
        </ToolbarMenu>

        <div style={{ flex: 1 }} />

        <span style={{ color: theme.palette.text?.secondary, fontSize: 12, whiteSpace: 'nowrap' }}>
          {`${n(sourcesCount)} ${t_i18n('objects')} · ${n(targetsCount)} ${t_i18n('correlated targets')}`}
        </span>

        {overCorrelated.length > 0 && (
          <>
            <Divider sx={{ margin: 1, height: '60%' }} orientation="vertical" />
            <ToolbarMenuBadge objects={overCorrelated} />
          </>
        )}
      </div>
    </Drawer>
  );
};

// The objects set aside by the over-correlation threshold. They are never
// dropped silently: they stay one click away, with their correlation degree.
const ToolbarMenuBadge = ({ objects }: { objects: OverCorrelatedObject[] }) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  return (
    <>
      <Tooltip title={t_i18n('Over-correlating objects, hidden')}>
        <IconButton
          color="warning"
          onClick={(event: MouseEvent<HTMLButtonElement>) => setAnchorEl(event.currentTarget)}
        >
          <Badge badgeContent={objects.length} color="warning">
            <WarningAmberOutlined fontSize="small" />
          </Badge>
        </IconButton>
      </Tooltip>
      <Menu
        anchorEl={anchorEl}
        open={!!anchorEl}
        onClose={() => setAnchorEl(null)}
        anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
        transformOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <ListSubheader>{t_i18n('Over-correlating objects, hidden')}</ListSubheader>
        {objects.slice(0, 30).map((object) => (
          <MenuItem key={object.id} dense>
            <ItemIcon type={object.entityType} size="small" />
            <ListItemText
              sx={{ marginLeft: 1 }}
              primary={object.label}
              secondary={`${object.total} ${t_i18n('containers')}`}
            />
          </MenuItem>
        ))}
      </Menu>
    </>
  );
};

export default CorrelationTimelineToolbar;
