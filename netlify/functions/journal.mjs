import { getStore } from "@netlify/blobs";
import { handleJournal } from "../lib/core.mjs";

export default async (req) => handleJournal(req, getStore({ name: "quran-journal", consistency: "strong" }));

export const config = { path: "/api/journal" };
