import { getStore } from "@netlify/blobs";
import * as wa from "@simplewebauthn/server";
import { handlePasskey } from "../lib/core.mjs";

export default async (req) => handlePasskey(req, getStore({ name: "quran-journal", consistency: "strong" }), wa);

export const config = { path: "/api/passkey" };
