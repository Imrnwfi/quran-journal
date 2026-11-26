import { getStore } from "@netlify/blobs";
import { handleTGroup } from "../lib/core.mjs";

export default async (req) => handleTGroup(req, getStore({ name: "quran-journal", consistency: "strong" }));

export const config = { path: "/api/tgroup" };
