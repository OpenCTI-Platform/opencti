class OpenCTIApiPir:
    """OpenCTIApiPir"""

    def __init__(self, api):
        self.api = api

    def pir_flag_element(self, **kwargs):
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        query = """
            mutation PirFlagElement($id: ID!, $input: PirFlagElementInput!) {
                pirFlagElement(id: $id, input: $input)
            }
           """
        self.api.query(
            query,
            {
                "id": id,
                "input": input,
            },
        )

    def pir_unflag_element(self, **kwargs):
        id = kwargs.get("id", None)
        input = kwargs.get("input", None)
        query = """
            mutation PirUnflagElement($id: ID!, $input: PirUnflagElementInput!) {
                pirUnflagElement(id: $id, input: $input)
            }
           """
        self.api.query(
            query,
            {
                "id": id,
                "input": input,
            },
        )
