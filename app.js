import express from "express";
import config from "./config.json" assert { type: "json" };
import { readFileSync } from "node:fs";
import path from "node:path";
import { SignJWT, importJWK, createRemoteJWKSet, jwtVerify } from "jose";
import NodeCache from "node-cache";
import assert from "node:assert";
import axiosLib from "axios";

const axios = axiosLib.create({ baseURL: config.SIGN_BASE_URL });
const cache = new NodeCache({ stdTTL: 5400 });
const app = express();

app.use(express.json());
app.use(express.static("frontend"));

const createJwt = async (payload) => {
  return new SignJWT(payload)
    .setIssuedAt()
    .setProtectedHeader({
      alg: "ES256",
      kid: config.CLIENT_PRIVATE_KEY.kid,
    })
    .setJti(crypto.randomUUID())
    .setExpirationTime("120s")
    .sign(await importJWK(config.CLIENT_PRIVATE_KEY));
};

app.get("/sign", async (req, res) => {
  try {
    const payload = {
      x: 0.5,
      y: 0.5,
      page: 1,
      doc_name: "dummy.pdf",
      client_id: config.CLIENT_ID,
    };

    const pdfBuffer = readFileSync(path.join(process.cwd(), "dummy.pdf"));

    const createSignRequestResponse = await axios.post("/sign-requests", pdfBuffer, {
      headers: {
        "Content-Type": "application/octet-stream",
        Authorization: await createJwt(payload),
      },
    });

    const { signing_url, request_id, exchange_code } = createSignRequestResponse.data;
    cache.set(`exchange_code::${request_id}`, exchange_code);

    return res.redirect(signing_url);
  } catch (error) {
    console.error("SIGN ERROR:", error?.response?.data || error);
    return res.status(500).send("Sign failed");
  }
});

app.get("/sign-requests/:request_id", async (req, res) => {
  try {
    const { request_id } = req.params;

    const exchange_code = cache.get(`exchange_code::${request_id}`);
    assert(exchange_code);

    const {
      data: { signed_doc_url },
    } = await axios.get(`/sign-requests/${request_id}/signed_doc`, {
      headers: { Authorization: await createJwt({ exchange_code }) },
    });

    const file = await axios.get(signed_doc_url, { responseType: "stream" });

    res.setHeader("Content-Disposition", `attachment; filename="signed_${request_id}.pdf"`);
    res.setHeader("Content-Type", "application/pdf");
    return file.data.pipe(res);
  } catch (error) {
    console.error("DOWNLOAD ERROR:", error);
    return res.status(500).send("Download failed");
  }
});

app.get("/jwks", (req, res) => {
  const { d, ...publicJwk } = { ...config.CLIENT_PRIVATE_KEY };
  return res.status(200).json({ keys: [publicJwk] });
});

app.post("/webhook", async (req, res) => {
  try {
    const token = req.body.token;
    assert(token);

    const { payload } = await jwtVerify(
      token,
      createRemoteJWKSet(new URL(config.SIGN_JWKS_URL))
    );

    console.log("Webhook received:", payload);
    return res.status(200).send("OK");
  } catch (error) {
    console.error("WEBHOOK ERROR:", error);
    return res.status(500).send("Webhook failed");
  }
});

export default app;