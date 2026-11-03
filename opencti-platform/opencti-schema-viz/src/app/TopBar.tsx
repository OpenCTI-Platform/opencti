import { Button, Header, HeaderGroup, Icon, Text } from '@filigran/design-system';
import { NavigationBreadcrumb } from '../features/breadcrumb/NavigationBreadcrumb';
import { useSchemaGraphStore } from '../state/schemaGraphStore';
import type { ThemeMode } from '../shared/theme/useTheme';
import { IconAction } from '../shared/ui/IconAction';

interface TopBarProps {
  theme: ThemeMode;
  onToggleTheme: () => void;
}

export const TopBar = ({ theme, onToggleTheme }: TopBarProps) => {
  const findPathOpen = useSchemaGraphStore((state) => state.findPath.open);
  const openFindPath = useSchemaGraphStore((state) => state.openFindPath);
  const closeFindPath = useSchemaGraphStore((state) => state.closeFindPath);
  const selectedTypeId = useSchemaGraphStore((state) => state.selectedTypeId);

  return (
    <Header className="sv-header" fullWidth={false}>
      <HeaderGroup className="sv-header__brand">
        <Icon name="custom/opencti" size={24} />
        <Text variant="title-xs" as="span">Data model</Text>
      </HeaderGroup>
      <HeaderGroup grow="unbounded" separatorBefore>
        <NavigationBreadcrumb />
      </HeaderGroup>
      <HeaderGroup>
        <Button
          priority={findPathOpen ? 'primary' : 'secondary'}
          startIcon={<Icon name="route" size={16} />}
          data-find-path-trigger
          aria-expanded={findPathOpen}
          onClick={() => (findPathOpen ? closeFindPath() : openFindPath(selectedTypeId ?? undefined))}
        >
          Find path
        </Button>
        <IconAction icon={theme === 'dark' ? 'sun' : 'moon'} label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'} onClick={onToggleTheme} size="md" />
      </HeaderGroup>
    </Header>
  );
};
