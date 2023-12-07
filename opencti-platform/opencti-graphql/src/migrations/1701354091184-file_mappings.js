import { elUpdateMapping, isElkEngine } from '../database/engine';

export const up = async (next) => {
  const flattenedType = isElkEngine() ? 'flattened' : 'flat_object';
  await elUpdateMapping({
    name: {
      type: 'text',
      fields: {
        keyword: {
          type: 'keyword',
          normalizer: 'string_normalizer',
          ignore_above: 512,
        },
      },
    },
    size: {
      type: 'integer',
    },
    lastModifiedSinceMin: {
      type: 'integer',
    },
    lastModified: {
      type: 'date',
    },
    metaData: {
      properties: {
        order: {
          type: 'integer',
        },
        inCarousel: {
          type: 'boolean',
        },
        messages: { type: flattenedType },
        errors: { type: flattenedType },
      },
    }
  });
  next();
};

export const down = async (next) => {
  next();
};
