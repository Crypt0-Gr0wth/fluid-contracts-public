import { BigNumber, utils } from "ethers";

// secp256k1 curve order; signatures with s > n/2 are valid ECDSA but rejected by
// Ethereum nodes (EIP-2), and KMS returns high-s roughly half the time.
const SECP256K1_N = BigNumber.from("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const SECP256K1_HALF_N = SECP256K1_N.div(2);

export interface KmsSignerOptions {
  keyId: string;
  // when set, the address derived from the KMS public key must match this, so a
  // misconfigured key id / redirected endpoint fails loudly instead of deploying
  // the whole stack under an unexpected deployer.
  expectedAddress?: string;
}

/**
 * Signs Ethereum digests with an AWS KMS ECC_SECG_P256K1 key. The private key
 * never leaves KMS: the address comes from GetPublicKey, signatures from Sign
 * (MessageType DIGEST — KMS must not hash again), and the recovery id is
 * reconstructed locally by matching the recovered address.
 *
 * AWS SDK v3 is loaded lazily so the dependency is only needed once a network
 * actually configures `kmsKeyId`. Region/credentials/endpoint come from the
 * standard AWS env/config chain (AWS_REGION, AWS_ENDPOINT_URL, role creds).
 */
export class KmsEthSigner {
  private readonly keyId: string;
  private readonly expectedAddress?: string;
  private client: any;
  private sdk: any;
  private addressPromise?: Promise<string>;

  constructor(options: KmsSignerOptions) {
    this.keyId = options.keyId;
    this.expectedAddress = options.expectedAddress;
  }

  private loadSdk() {
    if (!this.sdk) {
      // FLUID_KMS_SDK_PATH is a PoC-only escape hatch until @aws-sdk/client-kms
      // is a devDependency; drop it when the dependency lands.
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      this.sdk = require(process.env.FLUID_KMS_SDK_PATH || "@aws-sdk/client-kms");
      this.client = new this.sdk.KMSClient({});
    }
    return this.sdk;
  }

  getAddress(): Promise<string> {
    if (!this.addressPromise) {
      this.addressPromise = this.deriveAddress();
    }
    return this.addressPromise;
  }

  private async deriveAddress(): Promise<string> {
    const sdk = this.loadSdk();
    const res = await this.client.send(new sdk.GetPublicKeyCommand({ KeyId: this.keyId }));
    if (res.KeySpec !== "ECC_SECG_P256K1") {
      throw new Error(`KMS key ${this.keyId} has KeySpec ${res.KeySpec}, need ECC_SECG_P256K1`);
    }
    if (res.KeyUsage !== "SIGN_VERIFY") {
      throw new Error(`KMS key ${this.keyId} has KeyUsage ${res.KeyUsage}, need SIGN_VERIFY`);
    }
    // DER SPKI ends with the BIT STRING payload: 0x04 || X || Y (65 bytes).
    const spki: Uint8Array = res.PublicKey;
    const point = spki.slice(spki.length - 65);
    if (point[0] !== 0x04) {
      throw new Error(`KMS public key for ${this.keyId} is not an uncompressed secp256k1 point`);
    }
    const address = utils.computeAddress(point);
    if (this.expectedAddress && address.toLowerCase() !== this.expectedAddress.toLowerCase()) {
      throw new Error(
        `KMS key ${this.keyId} derives deployer ${address} but expected ${this.expectedAddress} — refusing to sign`
      );
    }
    return address;
  }

  async signDigest(digest: utils.BytesLike): Promise<utils.Signature> {
    const address = await this.getAddress();
    const sdk = this.loadSdk();
    const res = await this.client.send(
      new sdk.SignCommand({
        KeyId: this.keyId,
        Message: utils.arrayify(digest),
        MessageType: "DIGEST",
        SigningAlgorithm: "ECDSA_SHA_256",
      })
    );

    const { r, s } = parseDerSignature(res.Signature);
    // EIP-2: canonicalize to low-s; N - s is the same signature's other representation.
    const lowS = s.gt(SECP256K1_HALF_N) ? SECP256K1_N.sub(s) : s;

    // DER carries no recovery id; try both parities against the known address.
    for (const recoveryParam of [0, 1]) {
      const signature = utils.splitSignature({
        r: utils.hexZeroPad(r.toHexString(), 32),
        s: utils.hexZeroPad(lowS.toHexString(), 32),
        recoveryParam,
      });
      if (utils.recoverAddress(digest, signature).toLowerCase() === address.toLowerCase()) {
        return signature;
      }
    }
    throw new Error(`KMS signature for ${this.keyId} does not recover to ${address}`);
  }
}

// ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } — the exact blob KMS
// returns. Content is < 128 bytes so only short-form lengths occur; assert it.
export function parseDerSignature(der: Uint8Array): { r: BigNumber; s: BigNumber } {
  if (der[0] !== 0x30 || der[1] & 0x80) {
    throw new Error("unexpected DER signature framing from KMS");
  }
  const readInt = (offset: number): { value: BigNumber; next: number } => {
    if (der[offset] !== 0x02) {
      throw new Error("expected DER INTEGER in KMS signature");
    }
    const length = der[offset + 1];
    const bytes = der.slice(offset + 2, offset + 2 + length);
    return { value: BigNumber.from(utils.hexlify(bytes)), next: offset + 2 + length };
  };
  const rInt = readInt(2);
  const sInt = readInt(rInt.next);
  return { r: rInt.value, s: sInt.value };
}
