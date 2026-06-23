import requests

# Variables
api_url = #TO_COMPLETE (ex : "http://opencti:4000")
api_token = #TO_COMPLETE
exclusion_list_id = #TO_COMPLETE (ex :"y50ea9c3-2aaa-4843-aa94-f0235162c6bf")
txt_file_path = #TO_COMPLETE (ex : "/my_exclusion_list.txt")

MUTATION = """
  mutation exclusionListFileUpdate($id: ID!, $input: [EditInput!], $file: Upload) {
    exclusionListFieldPatch(id: $id, input: $input, file: $file) {
      id
      file_id
      exclusion_list_values_count
      exclusion_list_file_size
    }
  }
"""

# GraphQL multipart request to find the exclusion list
operations = {
    "query": MUTATION,
    "variables": {
        "id": exclusion_list_id,
        "input": [],   
        "file": None   
    }
}

map_data = {
    "0": ["variables.file"]
}

# Replace the exclusion list content with the text file content
with open(txt_file_path, "rb") as f:
    response = requests.post(
        f"{api_url}/graphql",
        headers={"Authorization": f"Bearer {api_token}"},
        data={
            "operations": __import__("json").dumps(operations),
            "map": __import__("json").dumps(map_data),
        },
        files={"0": (txt_file_path.split("/")[-1], f, "text/plain")},
    )

print(response.json())