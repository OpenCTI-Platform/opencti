# coding: utf-8


def test_create_entity_with_embedded_file(api_client):
    with open("tests/data/upload_image_example.png", "rb") as file:
        file_data = file.read()

    intrusion_set = api_client.intrusion_set.create(
        name="Intrusion Set with embedded file",
        description="Description\n\n![Image example](embedded/upload_image_example.png)",
        first_seen="2026-02-11T23:40:53.575Z",
        last_seen="2026-02-12T23:40:53.575Z",
        update=True,
        files=(api_client.file("upload_image_example.png", file_data, "image/png")),
        embedded=True,
    )

    assert intrusion_set is not None, "Intrusion-Set is NoneType"
