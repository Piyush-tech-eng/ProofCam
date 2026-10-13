import { createHash } from "node:crypto";
import { Connection, PublicKey, SystemProgram, Transaction, TransactionInstruction, type Commitment } from "@solana/web3.js";
import type { OnChainCaptureRecord, RecordSummary, SignedCapturePackage } from "./types.js";
import { hexToBytes, isValidSha256Hex } from "./hashing.js";
import type { VerificationSource } from "./verify.js";

const ACCOUNT_DISCRIMINATOR = createHash("sha256").update("account:CaptureRecord").digest().subarray(0, 8);
const MAX_MANIFEST_BYTES = 1024 * 1024;
const REGISTER_CAPTURE_DISCRIMINATOR = createHash("sha256").update("global:register_capture").digest().subarray(0, 8);

export interface SolanaSourceOptions {
  rpcUrl: string;
  programId: string;
  commitment?: Commitment;
  /** HTTP IPFS gateway base URL, for example https://ipfs.io/ipfs. */
  manifestGatewayUrl?: string;
}

export interface RegisterCaptureTransactionOptions {
  rpcUrl: string;
  programId: string;
  authority: string;
  captureId: string;
  imageHash: string;
  manifestHash: string;
  manifestCid: string;
  locationGeohash: string | null;
}

function encodeString(value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32LE(bytes.length);
  return Buffer.concat([prefix, bytes]);
}

/**
 * Create the unsigned Anchor register_capture transaction for an external wallet to sign.
 * The returned transaction has a fresh blockhash and the authority set as fee payer.
 */
export async function buildRegisterCaptureTransaction(options: RegisterCaptureTransactionOptions): Promise<{
  transactionBase64: string;
  blockhash: string;
  lastValidBlockHeight: number;
  captureRecordAddress: string;
}> {
  if (!/^[0-9a-f]{64}$/.test(options.captureId)) throw new Error("Capture ID must be 32-byte lowercase hex");
  if (!isValidSha256Hex(options.imageHash) || !isValidSha256Hex(options.manifestHash)) throw new Error("Hashes must be lowercase SHA-256 hex");
  if (!/^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{9,})$/.test(options.manifestCid) || options.manifestCid.length > 64) {
    throw new Error("Manifest CID must be a supported CIDv0 or CIDv1 of at most 64 characters");
  }
  if (options.locationGeohash !== null && !/^[0123456789bcdefghjkmnpqrstuvwxyz]{1,12}$/.test(options.locationGeohash)) {
    throw new Error("Location geohash is invalid");
  }

  const programId = new PublicKey(options.programId);
  const authority = new PublicKey(options.authority);
  const captureId = Buffer.from(hexToBytes(options.captureId));
  const [captureRecord] = PublicKey.findProgramAddressSync([Buffer.from("capture"), captureId], programId);
  const encodedLocation = options.locationGeohash === null
    ? Buffer.from([0])
    : Buffer.concat([Buffer.from([1]), encodeString(options.locationGeohash)]);
  const instructionData = Buffer.concat([
    REGISTER_CAPTURE_DISCRIMINATOR,
    captureId,
    Buffer.from(hexToBytes(options.imageHash)),
    Buffer.from(hexToBytes(options.manifestHash)),
    encodeString(options.manifestCid),
    encodedLocation,
    Buffer.from([1]), // schema version
  ]);
  const instruction = new TransactionInstruction({
    programId,
    keys: [
      { pubkey: captureRecord, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: instructionData,
  });
  const connection = new Connection(options.rpcUrl, "confirmed");
  const latest = await connection.getLatestBlockhash("confirmed");
  const transaction = new Transaction({ feePayer: authority, ...latest }).add(instruction);
  const serialized = transaction.serialize({ requireAllSignatures: false, verifySignatures: false });
  return {
    transactionBase64: serialized.toString("base64"),
    blockhash: latest.blockhash,
    lastValidBlockHeight: latest.lastValidBlockHeight,
    captureRecordAddress: captureRecord.toBase58(),
  };
}

interface DecodedRecord extends OnChainCaptureRecord {
  address: PublicKey;
}

function decodeRecord(address: PublicKey, data: Buffer): DecodedRecord {
  if (data.length < 8 || !data.subarray(0, 8).equals(ACCOUNT_DISCRIMINATOR)) {
    throw new Error("Account discriminator does not match CaptureRecord");
  }
  let offset = 8;
  const take = (length: number): Buffer => {
    if (length < 0 || offset + length > data.length) throw new Error("CaptureRecord data is truncated");
    const bytes = data.subarray(offset, offset + length);
    offset += length;
    return bytes;
  };
  const readString = (maxBytes: number): string => {
    const length = take(4).readUInt32LE(0);
    if (length > maxBytes) throw new Error("CaptureRecord string exceeds its allowed size");
    return take(length).toString("utf8");
  };
  const captureId = take(32).toString("hex");
  const imageHash = take(32).toString("hex");
  const manifestHash = take(32).toString("hex");
  const authority = new PublicKey(take(32)).toBase58();
  const registeredAt = Number(take(8).readBigInt64LE(0));
  const manifestCid = readString(64);
  const hasLocation = take(1).readUInt8();
  if (hasLocation > 1) throw new Error("Invalid Option<String> marker in CaptureRecord");
  const locationGeohash = hasLocation === 1 ? readString(12) : null;
  const schemaVersion = take(1).readUInt8();
  take(1); // Anchor PDA bump byte
  return { captureId, imageHash, manifestHash, authority, registeredAt, manifestCid, locationGeohash, schemaVersion, address };
}

function summary(record: DecodedRecord, signature: string | null): RecordSummary {
  return {
    capture_id: record.captureId,
    authority: record.authority,
    registered_at: record.registeredAt,
    transaction_signature: signature,
    explorer_url: signature ? "https://explorer.solana.com/tx/" + signature + "?cluster=devnet" : null,
    registry: "solana_devnet",
  };
}

function cidUrl(gateway: string, cid: string): string | null {
  const normalized = cid.startsWith("ipfs://") ? cid.slice("ipfs://".length) : cid;
  // IPFS CIDv0 or CIDv1 base32 only; reject synthetic local-demo identifiers.
  if (/^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{9,})$/.test(normalized)) return gateway.replace(/\/+$/, "") + "/" + encodeURIComponent(normalized);
  return null;
}

/** Solana Devnet registry and content-addressed manifest reader. */
export function createSolanaVerificationSource(options: SolanaSourceOptions): VerificationSource {
  const connection = new Connection(options.rpcUrl, options.commitment ?? "confirmed");
  const programId = new PublicKey(options.programId);
  const gateway = options.manifestGatewayUrl ?? "https://ipfs.io/ipfs";

  const readRecord = async (address: PublicKey): Promise<DecodedRecord | null> => {
    const account = await connection.getAccountInfo(address);
    if (!account) return null;
    if (!account.owner.equals(programId)) throw new Error("Capture account owner does not match the configured program");
    return decodeRecord(address, account.data);
  };

  const findAddress = (captureId: string): PublicKey => {
    if (!/^[0-9a-f]{64}$/.test(captureId)) throw new Error("Capture ID must be 32 bytes encoded as lowercase hex");
    const bytes = Buffer.from(hexToBytes(captureId));
    return PublicKey.findProgramAddressSync([Buffer.from("capture"), bytes], programId)[0];
  };

  const fetchSignature = async (address: PublicKey): Promise<string | null> => {
    try {
      const signatures = await connection.getSignaturesForAddress(address, { limit: 1 });
      return signatures[0]?.signature ?? null;
    } catch {
      return null;
    }
  };

  const present = async (record: DecodedRecord) => ({ record, summary: summary(record, await fetchSignature(record.address)) });

  return {
    async getRecordByCaptureId(captureId) {
      const record = await readRecord(findAddress(captureId));
      return record ? present(record) : null;
    },
    async findRecordsByImageHash(imageHash) {
      if (!isValidSha256Hex(imageHash)) throw new Error("Image hash must be lowercase SHA-256 hex");
      const hashKey = new PublicKey(Buffer.from(hexToBytes(imageHash))).toBase58();
      const accounts = await connection.getProgramAccounts(programId, {
        commitment: options.commitment ?? "confirmed",
        filters: [{ memcmp: { offset: 8 + 32, bytes: hashKey } }],
      });
      const results: Array<{ record: OnChainCaptureRecord; summary: RecordSummary }> = [];
      for (const account of accounts) {
        const record = decodeRecord(account.pubkey, account.account.data);
        results.push(await present(record));
      }
      return results;
    },
    async getManifest(cid): Promise<SignedCapturePackage | null> {
      const target = cidUrl(gateway, cid);
      if (!target) return null;
      const response = await fetch(target, { signal: AbortSignal.timeout(10_000) });
      if (!response.ok) throw new Error("Manifest gateway returned HTTP " + response.status);
      const length = Number(response.headers.get("content-length") ?? 0);
      if (length > MAX_MANIFEST_BYTES) throw new Error("Manifest exceeds the 1 MiB limit");
      const text = await response.text();
      if (Buffer.byteLength(text, "utf8") > MAX_MANIFEST_BYTES) throw new Error("Manifest exceeds the 1 MiB limit");
      return JSON.parse(text) as SignedCapturePackage;
    },
  };
}
