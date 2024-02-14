/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
import type { NextApiRequest, NextApiResponse } from "next";
import type { LoralNonce } from "@/server/api/routers/loral";
import {
  OAUTH_CLIENT_ID,
  OAUTH_CLIENT_SECRET,
  REDIRECT_URI,
  SERVER_SLUG,
} from "@/server/api/routers/loral";
import axios from "axios";
import { db } from "@/server/db";

export default async function callback(
  req: NextApiRequest,
  res: NextApiResponse,
) {
  const { code, state } = req.query;

  if (!code || !state) {
    return res.status(400).json({ error: "Code or UserId not provided" });
  }

  // parse state, it should be of type LoralNonce, and verify the CSRF token
  const nonce: LoralNonce = JSON.parse(state as string);
  const user = await db.user.findFirstOrThrow({
    where: {
      id: Number(nonce.userId),
    },
  });
  const savedNonce: LoralNonce = JSON.parse(user.loralNonce!);
  if (nonce.csrf !== savedNonce.csrf) {
    return res.status(400).json({ error: "CSRF token mismatch" });
  }

  // exchange the authorization code for an access and refresh token
  // refresh token
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    code: code as string,
    redirect_uri: REDIRECT_URI,
  });
  const config = {
    headers: {
      Authorization: `Basic ${Buffer.from(`${OAUTH_CLIENT_ID}:${OAUTH_CLIENT_SECRET}`).toString("base64")}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
  };
  const response = await axios.post(
    `${SERVER_SLUG}/oauth2/token`,
    params,
    config,
  );

  if (response.status !== 200) {
    return res
      .status(500)
      .json({ error: "Failed to exchange code for tokens" });
  }

  try {
    const access_token = response.data.access_token! as string;
    const refresh_token = response.data.refresh_token! as string;
    const expires_in = response.data.expires_in! as number;
    const scope = response.data.scope! as string;

    // store the tokens in the user's database record
    await db.user.update({
      where: {
        id: Number(nonce.userId),
      },
      data: {
        loralAccessToken: access_token,
        loralRefreshToken: refresh_token,
        loralExpiresAt: new Date(Date.now() + expires_in * 1000),
      },
    });

    return res.status(200).json({ message: "Tokens stored successfully" });
  } catch (e) {
    return res
      .status(500)
      .json({ error: "Error getting tokens from response" });
  }
}
