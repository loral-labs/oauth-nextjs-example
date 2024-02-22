/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { createTRPCRouter, publicProcedure } from "@/server/api/trpc";
import crypto from "crypto";
import { getAccessToken } from "@/server/util";
import axios from "axios";

export const OAUTH_CLIENT_ID = "aca314fc-8db0-4840-857c-99343e7d40c7";
export const SERVER_SLUG = "https://auth.loral.dev";
export const REDIRECT_URI = "http://localhost:3000/api/callback";
export const OAUTH_SCOPES = "openid offline_access kroger";
export const LORAL_API = "http://api.loral.dev";
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
  searchKroger: publicProcedure.mutation(async ({ ctx }) => {
    const user = await ctx.db.user.findFirstOrThrow();

    const token = await getAccessToken(user.id);

    const queryParams = new URLSearchParams({
      "filter.term": "milk",
    });
    const res = await axios.get(
      `${LORAL_API}/kroger/execute/v1/products?${queryParams.toString()}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      },
    );
    const data = res.data;
    return JSON.stringify(data);
  }),
});
