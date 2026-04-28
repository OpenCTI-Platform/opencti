from typing import Callable


def rewrite_markdown_images(
    markdown: str,
    replace_image: Callable[[str, str, str], str],
) -> str:
    rewritten_chunks = []
    cursor = 0
    markdown_length = len(markdown)

    while cursor < markdown_length:
        image_start = markdown.find("![", cursor)
        if image_start == -1:
            rewritten_chunks.append(markdown[cursor:])
            break

        rewritten_chunks.append(markdown[cursor:image_start])
        alt_end = -1
        alt_index = image_start + 2
        while alt_index < markdown_length:
            alt_char = markdown[alt_index]
            if alt_char == "\\":
                alt_index += 2
                continue
            if alt_char == "]":
                alt_end = alt_index
                break
            alt_index += 1
        if (
            alt_end == -1
            or alt_end + 1 >= markdown_length
            or markdown[alt_end + 1] != "("
        ):
            # Keep malformed syntax untouched instead of dropping characters.
            rewritten_chunks.append(markdown[image_start])
            cursor = image_start + 1
            continue

        destination_start = alt_end + 2
        index = destination_start
        nested_parentheses = 0
        while index < markdown_length:
            char = markdown[index]
            if char == "\\":
                index += 2
                continue
            if char == "(":
                nested_parentheses += 1
            elif char == ")":
                if nested_parentheses == 0:
                    break
                nested_parentheses -= 1
            index += 1

        if index >= markdown_length or markdown[index] != ")":
            # Keep malformed syntax untouched instead of dropping characters.
            rewritten_chunks.append(markdown[image_start])
            cursor = image_start + 1
            continue

        full_match = markdown[image_start : index + 1]
        alt_text = markdown[image_start + 2 : alt_end]
        url = markdown[destination_start:index].strip()
        rewritten_chunks.append(replace_image(alt_text, url, full_match))
        cursor = index + 1

    return "".join(rewritten_chunks)
