import { z } from 'zod';
import { IngestionAuthType, TaxiiVersion } from '../../generated/graphql';

const markingReference = z.strictObject({
  standard_id: z.string().min(1),
  definition_type: z.string(),
  definition: z.string(),
});

const feedFields = {
  name: z.string().trim().min(2, 'Feed name must be at least 2 characters'),
  description: z.string().nullable().optional(),
  scheduling_period: z.string().nullable().optional(),
  uri: z.string().min(5),
  ssl_verify: z.boolean().nullable().optional(),
  confidence_level: z.number().int().min(0).max(100).nullable().optional(),
};

const authenticationFields = {
  authentication_type: z.enum(IngestionAuthType),
};

const mapperRepresentations = z.array(z.looseObject({ attributes: z.array(z.looseObject({})) }));

export const rssFeedImportSchema = z.strictObject({
  ...feedFields,
  report_types: z.array(z.string()),
  markings: z.array(markingReference),
  author: z.strictObject({ standard_id: z.string().min(1), name: z.string() }).nullable().optional(),
});

export const csvFeedImportSchema = z.strictObject({
  ...feedFields,
  ...authenticationFields,
  markings: z.array(markingReference),
  csv_mapper: z.strictObject({
    name: z.string().nullable().optional(),
    has_header: z.boolean(),
    separator: z.string(),
    skipLineChar: z.string().nullable().optional(),
    representations: mapperRepresentations,
  }),
});

export const jsonFeedImportSchema = z.strictObject({
  ...feedFields,
  ...authenticationFields,
  markings: z.array(markingReference),
  verb: z.enum(['get', 'post']),
  body: z.string().nullable().optional(),
  headers: z.array(z.strictObject({ name: z.string().min(1), value: z.string() })),
  query_attributes: z.array(z.looseObject({})),
  pagination_with_sub_page: z.boolean().nullable().optional(),
  pagination_with_sub_page_attribute_path: z.string().nullable().optional(),
  pagination_with_sub_page_query_verb: z.enum(['get', 'post']).nullable().optional(),
  json_mapper: z.strictObject({
    name: z.string().trim().min(1),
    variables: z.array(z.looseObject({})),
    representations: mapperRepresentations,
  }),
});

export const taxiiFeedImportSchema = z.strictObject({
  ...feedFields,
  ...authenticationFields,
  version: z.enum(TaxiiVersion),
  collection: z.string().min(5),
  added_after_start: z.string().nullable().optional(),
  confidence_to_score: z.boolean().nullable().optional(),
});

export type FeedMarkingReference = z.infer<typeof markingReference>;
export type RssFeedImportConfiguration = z.infer<typeof rssFeedImportSchema>;
export type CsvFeedImportConfiguration = z.infer<typeof csvFeedImportSchema>;
export type JsonFeedImportConfiguration = z.infer<typeof jsonFeedImportSchema>;
export type TaxiiFeedImportConfiguration = z.infer<typeof taxiiFeedImportSchema>;
export type FeedImportConfiguration = RssFeedImportConfiguration | CsvFeedImportConfiguration | JsonFeedImportConfiguration | TaxiiFeedImportConfiguration;
