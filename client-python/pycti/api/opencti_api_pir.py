class OpenCTIApiPir:
    """OpenCTI PIR (Priority Intelligence Requirements) API class.

    Manages PIR flagging operations on elements.

    :param api: instance of :py:class:`~pycti.api.opencti_api_client.OpenCTIApiClient`
    :type api: OpenCTIApiClient
    """

    def __init__(self, api):
        self.api = api

    def pir_flag_element(self, **kwargs):
        """Flag an element with a PIR.

        :param id: the element id
        :type id: str
        :param input: the PIR flag input (PirFlagElementInput format)
        :type input: dict
        :return: None
        :rtype: None
        """
        element_id = kwargs.get("id", None)
        pir_input = kwargs.get("input", None)
        query = """
            mutation PirFlagElement($id: ID!, $input: PirFlagElementInput!) {
                pirFlagElement(id: $id, input: $input)
            }
           """
        self.api.query(
            query,
            {
                "id": element_id,
                "input": pir_input,
            },
        )

    def pir_unflag_element(self, **kwargs):
        """Unflag an element from a PIR.

        :param id: the element id
        :type id: str
        :param input: the PIR unflag input (PirUnflagElementInput format)
        :type input: dict
        :return: None
        :rtype: None
        """
        element_id = kwargs.get("id", None)
        pir_input = kwargs.get("input", None)
        query = """
            mutation PirUnflagElement($id: ID!, $input: PirUnflagElementInput!) {
                pirUnflagElement(id: $id, input: $input)
            }
           """
        self.api.query(
            query,
            {
                "id": element_id,
                "input": pir_input,
            },
        )
