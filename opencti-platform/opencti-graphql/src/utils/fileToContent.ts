import {streamToString} from "../database/file-storage";
import type {FileHandle} from "fs/promises";

export async function extractContentFrom(file: Promise<FileHandle>) {
    const uploadedFile = await file;
    const readStream = uploadedFile.createReadStream();
    const fileContent = await streamToString(readStream);
    return JSON.parse(fileContent.toString());
}