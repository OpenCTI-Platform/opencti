export const addToInventoryQuery = (assetIri) => {
  if (!assetIri.startsWith('<')) assetIri = `<${assetIri}>`;
  return `
  INSERT {
    GRAPH ?g {
      ?inv <http://csrc.nist.gov/ns/oscal/common#assets> ${assetIri}
    } 
  } WHERE {
    GRAPH ?g {
      ?inv a <http://csrc.nist.gov/ns/oscal/common#AssetInventory> 
    }
  }
  `;
};

export const removeFromInventoryQuery = (assetIri) => {
  if (!assetIri.startsWith('<')) assetIri = `<${assetIri}>`;
  return `
  DELETE {
    GRAPH ?g {
      ?inv <http://csrc.nist.gov/ns/oscal/common#assets> ${assetIri} .
    }
  } WHERE {
    GRAPH ?g {
      ?inv a <http://csrc.nist.gov/ns/oscal/common#AssetInventory> .
    }
  }
  `;
};

export const deleteQuery = (id) => {
  return `
  DELETE {
    GRAPH ?g{
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ?g{
      ?iri a <http://scap.nist.gov/ns/asset-identification#Asset> .
      ?iri <http://darklight.ai/ns/common#id> "${id}". 
      ?iri ?p ?o
    }
  }
  `;
};
