class OpenCTIApiInferred:
    """OpenCTIApiInferred"""

    def __init__(self, api):
        self.api = api

    def create_inferred_rel(self, **kwargs):
        input = kwargs.get("input", None)
        self.api.app_logger.info("Creating inferred rel", {"input": input})
        query = """
            mutation inferredRelationAdd($jsonInput: String!) {
                inferredRelationAdd(jsonInput: $jsonInput)
            }
           """
        self.api.query(query, {"jsonInput": input})

    def create_inferred_entity(self, **kwargs):
        input = kwargs.get("input", None)
        self.api.app_logger.info("Creating inferred entity", {"input": input})
        query = """
            mutation inferredEntityAdd($jsonInput: String!) {
                inferredEntityAdd(jsonInput: $jsonInput)
            }
           """
        self.api.query(query, {"jsonInput": input})
