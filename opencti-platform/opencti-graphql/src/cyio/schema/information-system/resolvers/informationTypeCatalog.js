import {
  findAllInformationTypeCatalogs,
  findInformationTypeCatalogById,
  createInformationTypeCatalog,
  deleteInformationTypeCatalogById,
  editInformationTypeCatalogById,
  addInformationTypeToCatalog,
  removeInformationTypeFromCatalog,
} from '../domain/informationTypeCatalog.js';
import { findInformationTypeEntryByIri } from '../domain/informationTypeEntry.js';
  
const cyioInformationTypeCatalogResolvers = {
  Query: {
    // Information Type Catalog
    informationTypeCatalogs: async (_, args, { dbName, dataSources, selectMap }) => findAllInformationTypeCatalogs(args, dbName, dataSources, selectMap),
    informationTypeCatalog: async (_, { id }, { dbName, dataSources, selectMap }) => findInformationTypeCatalogById(id, dbName, dataSources, selectMap),
  },
  Mutation: {
    // Information Type Catalog
    createInformationTypeCatalog: async (_, { input }, { dbName, selectMap, dataSources }) => createInformationTypeCatalog(input, dbName, selectMap, dataSources),
    deleteInformationTypeCatalog: async (_, { id }, { dbName, dataSources }) => deleteInformationTypeCatalogById( id, dbName, dataSources),
    deleteInformationTypeCatalogs: async (_, { ids }, { dbName, dataSources }) => deleteInformationTypeCatalogById( ids, dbName, dataSources),
    editInformationTypeCatalog: async (_, { id, input }, { dbName, dataSources, selectMap }, {schema}) => editInformationTypeCatalogById(id, input, dbName, dataSources, selectMap, schema),
    // Attach & Detach
    addInformationTypeToCatalog: async (_, { id, entryId }, { dbName, dataSources, selectMap }) => addInformationTypeToCatalog(id, entryId, dbName, dataSources, selectMap),
    removeInformationTypeFromCatalog: async (_, { id, entryId }, { dbName, dataSources, selectMap }) => removeInformationTypeFromCatalog(id, entryId, dbName, dataSources, selectMap),
  },
  InformationTypeCatalog: {
    entries: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.entries_iri === undefined) return [];
      return findInformationTypeEntryByIri(parent.entries_iri, dataSources);
    },
    labels: async (parent, _, { dbName, dataSources, selectMap }) => {
    },
  },
};

export default cyioInformationTypeCatalogResolvers;
