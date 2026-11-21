import { Chip, Text } from '@filigran/design-system';
import type { SchemaType } from '../../data/schemaTypes';
import { useSchemaGraphStore } from '../../state/schemaGraphStore';
import { entityFamily } from '../../shared/theme/typeAppearance';

/** A type reference anywhere in the inspector: clicking it navigates to that type. */
export const TypeLink = ({ type, chip = false }: { type: SchemaType; chip?: boolean }) => {
  const focusType = useSchemaGraphStore((state) => state.focusType);
  if (chip) {
    const family = entityFamily(type);
    return (
      <Chip
        label={type.label}
        {...(family ? { entity: family } : { severity: 'neutral' as const })}
        onClick={() => focusType(type.id)}
        aria-label={`Go to ${type.label}`}
      />
    );
  }
  return (
    <Text variant="content-compact-link" as="button" type="button" className="sv-type-link" onClick={() => focusType(type.id)}>
      {type.label}
    </Text>
  );
};
