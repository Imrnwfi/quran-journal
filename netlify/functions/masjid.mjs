import { getStore } from "@netlify/blobs";
import { handleMasjid } from "../lib/core.mjs";

export default async (req) => handleMasjid(req, getStore({ name: "quran-journal", consistency: "strong" }));

export const config = { path: "/api/masjid" };
