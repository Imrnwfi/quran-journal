import { getStore } from "@netlify/blobs";
import * as wa from "@simplewebauthn/server";
import { handleAccount } from "../lib/core.mjs";

export default async (req) => handleAccount(req, getStore({ name: "quran-journal", consistency: "strong" }), wa);

export const config = { path: "/api/account" };
