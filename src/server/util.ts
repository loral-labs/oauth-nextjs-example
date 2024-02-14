import { db } from "@/server/db";
import {
  OAUTH_CLIENT_ID,
  OAUTH_CLIENT_SECRET,
  LORAL_API,
  SERVER_SLUG,
} from "@/server/api/routers/loral";
import axios from "axios";

export async function getAccessToken(userId: number) {
  const user = await db.user.findFirstOrThrow({
    where: {
      id: userId,
    },
  });

  if (
    typeof user.loralAccessToken !== "string" ||
    typeof user.loralRefreshToken !== "string" ||
    !(user.loralExpiresAt instanceof Date)
  ) {
    return null;
  }

  // check if access token is valid
  if (user.loralExpiresAt > new Date()) {
    return user.loralAccessToken;
  }

  // refresh token
  const params = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: user.loralRefreshToken,
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
  console.log(response.data);
}
