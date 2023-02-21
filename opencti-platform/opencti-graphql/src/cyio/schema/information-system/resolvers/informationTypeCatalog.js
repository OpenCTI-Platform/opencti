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
import { getReducer } from '../schema/sparql/informationTypeEntry.js';
  
const cyioInformationTypeCatalogResolvers = {
  Query: {
    // Information Type Catalog
    informationTypeCatalogs: async (_, args, { dbName, dataSources, selectMap }) => findAllInformationTypeCatalogs(args, dbName, dataSources, selectMap.getNode('node')),
    informationTypeCatalog: async (_, { id }, { dbName, dataSources, selectMap }) => findInformationTypeCatalogById(id, dbName, dataSources, selectMap.getNode('informationTypeCatalog')),
  },
  Mutation: {
    // Information Type Catalog
    createInformationTypeCatalog: async (_, { input }, { dbName, dataSources, selectMap }) => createInformationTypeCatalog(input, dbName, dataSources, selectMap.getNode('createInformationTypeCatalog')),
    deleteInformationTypeCatalog: async (_, { id }, { dbName, dataSources }) => deleteInformationTypeCatalogById( id, dbName, dataSources),
    deleteInformationTypeCatalogs: async (_, { ids }, { dbName, dataSources }) => deleteInformationTypeCatalogById( ids, dbName, dataSources),
    editInformationTypeCatalog: async (_, { id, input }, { dbName, dataSources, selectMap }, {schema}) => editInformationTypeCatalogById(id, input, dbName, dataSources, selectMap.getNode('editInformationTypeCatalog'), schema),
    // Attach & Detach
    addInformationTypeToCatalog: async (_, { id, entryId }, { dbName, dataSources }) => addInformationTypeToCatalog(id, entryId, dbName, dataSources),
    removeInformationTypeFromCatalog: async (_, { id, entryId }, { dbName, dataSources }) => removeInformationTypeFromCatalog(id, entryId, dbName, dataSources),
  },
  InformationTypeCatalog: {
    entries: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.entries_iri === undefined) return [];
      let results = [];
      for (let iri of parent.entries_iri) {
        let response = await findInformationTypeEntryByIri(iri, dbName, dataSources, selectMap.getNode('entries'));
        if (response === undefined || response == null) continue;
        results.push(response);
      }
      return results;
    },
    labels: async (parent, _, { dbName, dataSources, selectMap }) => {
    },
  },
};

export default cyioInformationTypeCatalogResolvers;
