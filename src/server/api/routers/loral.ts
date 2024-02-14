import { z } from "zod";
import { createTRPCRouter, publicProcedure } from "@/server/api/trpc";
import crypto from "crypto";
import axios from "axios";
import { getAccessToken } from "@/server/util";

export const OAUTH_CLIENT_ID = "aca314fc-8db0-4840-857c-99343e7d40c7";
export const SERVER_SLUG = "http://127.0.0.1:4000";
export const REDIRECT_URI = "http://127.0.0.1:3000/api/callback";
export const OAUTH_SCOPES = "openid offline_access kroger";
export const LORAL_API = "http://127.0.0.1:8081";
// Secrets: ensure the secrets below are never exposed to the client. This example app is not secure.
export const OAUTH_CLIENT_SECRET = "Bx5yUT0N5zBiexDGsMq4WO-wH";

export type LoralNonce = {
  csrf: string;
  userId: string;
};

export const loralRouter = createTRPCRouter({
  auth: publicProcedure.mutation(async ({ ctx }) => {
    const user = await ctx.db.user.findFirstOrThrow();

    // if any of the tokens are missing, the user has never authed to Loral
    if (
      typeof user?.loralAccessToken !== "string" ||
      typeof user?.loralRefreshToken !== "string" ||
      !(user?.loralExpiresAt instanceof Date)
    ) {
      const nonce: LoralNonce = {
        csrf: crypto.randomBytes(16).toString("hex"), // random nonce for CSRF protection
        userId: String(user.id), // to be used in the callback
      };
      const nonceString = JSON.stringify(nonce);
      await ctx.db.user.update({
        where: {
          id: user.id,
        },
        data: {
          loralNonce: nonceString,
        },
      });

      const queryParams = new URLSearchParams({
        response_type: "code",
        client_id: OAUTH_CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: OAUTH_SCOPES,
        state: nonceString,
      }).toString();
      return { redirect_uri: `${SERVER_SLUG}/oauth2/auth?${queryParams}` };
    }

    const freshAccessToken = await getAccessToken(user.id);
    return { token: freshAccessToken };
  }),
});
