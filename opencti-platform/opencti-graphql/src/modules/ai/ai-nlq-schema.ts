import {
  RegaringOfRelationshipSchema,
  RegaringOfEntityNameSchema,
  OperatorUnion,
  ModeUnion,
  EntityUnion,
  filterKeysSmall,
  FilterEnum,
} from "./ai-nlq-values";
import { z, ZodLiteral, ZodNever, ZodType } from "zod";
import type { ZodTypeDef } from "zod";

/**
 * Creates an array of Zod literal schemas with descriptions, based on the provided filter keys and filter definitions.
 *
 * @param filterKeys - An array of strings representing the keys for which to create Zod literal schemas.
 * @param FilterObject - An object mapping filter keys to their definitions. Each definition should contain a `description` property.
 * @returns An array of Zod literal schemas that include descriptions extracted from the FilterObject.
 */
export function createZodLiteralList(
  filterKeys: string[],
  FilterObject: Record<string, { description: string }>
): Array<z.ZodLiteral<string>> {
  return filterKeys.map((key: string) => {
    // Extract the description from the FilterObject's definition.
    return z.literal(key).describe(FilterObject[key]["description"]);
  });
}

/**
 * Creates a Zod union schema based on the provided filter keys and their definitions.
 *
 * Depending on the number of keys provided:
 * - If no keys are provided, returns `z.never()`.
 * - If one key is provided, returns the single Zod literal schema with its description.
 * - If multiple keys are provided, returns a Zod union of literal schemas.
 *
 * If a `unionDescription` is provided, the resulting schema will be annotated with that description.
 *
 * @param filterKeys - An array of strings representing the filter keys.
 * @param FilterObject - An object mapping filter keys to their definitions. Each definition must include a `description` property.
 * @param unionDescription - An optional string description to annotate the resulting union schema.
 * @returns A Zod schema which is one of:
 *          - A ZodNever schema if no keys are provided,
 *          - A single Zod literal schema if only one key is provided,
 *          - A Zod union of literal schemas if multiple keys are provided.
 */
export function createZodLiteralUnion(
  filterKeys: string[],
  FilterObject: Record<string, { description: string }>,
  unionDescription?: string
): ZodType<string, ZodTypeDef, string> | ZodNever {
  const literalList = createZodLiteralList(filterKeys, FilterObject);

  // Return appropriate schema based on how many keys were selected
  let resultUnion: ZodType<string, ZodTypeDef, string> | ZodNever;
  if (literalList.length === 0) {
    resultUnion = z.never();
  } else if (literalList.length === 1) {
    resultUnion = literalList[0];
  } else {
    // z.union requires a tuple with at least two schemas.
    resultUnion = z.union(
      literalList as [
        ZodLiteral<string>,
        ZodLiteral<string>,
        ...ZodLiteral<string>[]
      ]
    );
  }

  if (unionDescription) {
    resultUnion = resultUnion.describe(unionDescription);
  }

  return resultUnion;
}

// =======================
// RegardingOf
// =======================

const RegardingOfFilterItem = z
  .object({
    key: z
      .literal("regardingOf")
      .describe("The key of the 'regardingOf' filter, always 'regardingOf'."),
    values: z
      .array(
        z.union([RegaringOfRelationshipSchema, RegaringOfEntityNameSchema])
      )
      .describe("A list of entity name or relationship type filter values."),
    operator: OperatorUnion,
    mode: ModeUnion,
  })
  .describe(
    "A filter used to further refine entity filtering based on associated entities and/or relationships."
  );

// =======================
// Entities & Observables
// =======================

const EntityTypeFilterItem = z
  .object({
    key: z
      .literal("entity_type")
      .describe("The key of the entity type filter, always 'entity_type'."),
    values: z
      .array(EntityUnion)
      .describe("A list of entity type filter values."),
    operator: OperatorUnion,
    mode: ModeUnion,
  })
  .describe(
    "A filter used to filter entities by their type as defined by the STIX standard."
  );

// =======================
// Filter Schema using Filter Keys Subset without EntityType & RegardingOf
// =======================

const filterKeys = filterKeysSmall.filter(
  (key) => key !== FilterEnum.ENTITY_TYPE && key !== FilterEnum.REGARDING_OF
) as unknown as readonly [FilterEnum, ...FilterEnum[]];

const GenericFilterItem = z.object({
  key: z.enum(filterKeys).describe("The key of the filter."),
  values: z.array(z.string()).describe("A list of filter values."),
  operator: OperatorUnion,
  mode: ModeUnion,
});

// =======================
// Output Schema
// =======================

export const OutputSchema = z.object({
  filters: z
    .array(
      z.union([EntityTypeFilterItem, RegardingOfFilterItem, GenericFilterItem])
    )
    .describe("The list of filters applied to refine the OpenCTI query."),
  mode: ModeUnion,
});
