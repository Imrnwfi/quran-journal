import { getStore } from "@netlify/blobs";
import { handleGroup } from "../lib/core.mjs";

export default async (req) => handleGroup(req, getStore({ name: "quran-journal", consistency: "strong" }));

export const config = { path: "/api/group" };
