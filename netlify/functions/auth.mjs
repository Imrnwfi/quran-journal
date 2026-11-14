import { getStore } from "@netlify/blobs";
import { handleAuth } from "../lib/core.mjs";

export default async (req) => handleAuth(req, getStore({ name: "quran-journal", consistency: "strong" }));

export const config = { path: "/api/auth" };
