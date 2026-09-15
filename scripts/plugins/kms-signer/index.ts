import { extendProvider } from "hardhat/config";
import { ProviderWrapper } from "hardhat/plugins";
import { EIP1193Provider, HttpNetworkConfig, RequestArguments } from "hardhat/types";
import { BigNumber, utils } from "ethers";

import { KmsEthSigner } from "./signer";

declare module "hardhat/types/config" {
  interface HttpNetworkUserConfig {
    kmsKeyId?: string;
    kmsExpectedDeployer?: string;
    kmsExtraAccounts?: string[];
  }
  interface HttpNetworkConfig {
    kmsKeyId?: string;
    kmsExpectedDeployer?: string;
    kmsExtraAccounts?: string[];
  }
}

/**
 * EIP-1193 wrapper that makes the AWS KMS key the deployer account. Sits
 * directly on the raw HTTP provider (extendProvider), so hardhat's own
 * AutomaticSender/AutomaticGas/AutomaticGasPrice wrappers run first and every
 * eth_sendTransaction arrives with from/gas/fee fields populated — same slot
 * where LocalAccountsProvider signs when `accounts` holds a raw private key,
 * and the same architecture as @nomicfoundation/hardhat-ledger.
 *
 * eth_accounts answers with the KMS address first, so hardhat-deploy's named
 * accounts (deployer: 0), hre.ethers.getSigner() and hardhat-deploy's
 * from-based signing all resolve to KMS with no script changes.
 *
 * Hybrid mode: `kmsExtraAccounts` holds raw private keys that stay usable
 * NEXT TO the KMS deployer (test users, legacy flows). They are signed locally
 * in this same wrapper, routed by `from`; the KMS address always stays account
 * index 0 so the named deployer cannot silently shift to a local key — which
 * is exactly what would happen if a plain `accounts` array were configured
 * (hardhat would then install LocalAccountsProvider on top of this wrapper,
 * hide the KMS address from eth_accounts and reject its transactions; that
 * combination therefore stays a hard error).
 */
class KmsDeployerProvider extends ProviderWrapper {
  private chainIdPromise?: Promise<number>;
  private readonly extraKeys = new Map<string, utils.SigningKey>();

  constructor(provider: EIP1193Provider, private readonly signer: KmsEthSigner, extraAccounts: string[] = []) {
    super(provider);
    for (const privateKey of extraAccounts) {
      const key = new utils.SigningKey(privateKey);
      this.extraKeys.set(utils.computeAddress(key.publicKey).toLowerCase(), key);
    }
  }

  public async request(args: RequestArguments): Promise<unknown> {
    const params = this._getParams(args);
    switch (args.method) {
      case "eth_accounts":
      case "eth_requestAccounts":
        return [await this.signer.getAddress(), ...[...this.extraKeys.keys()].map(utils.getAddress)];
      case "eth_sendTransaction":
        return this.sendTransaction(params[0]);
      case "eth_sign":
        return this.signMessage(params[0], params[1]);
      case "personal_sign":
        return this.signMessage(params[1], params[0]);
      case "eth_signTypedData_v4":
        return this.signTypedData(params[0], params[1]);
      default:
        return this._wrappedProvider.request(args);
    }
  }

  /** KMS for the deployer, local SigningKey for a configured extra account, error otherwise. */
  private async signatureFor(from: string, digest: string, method: string): Promise<utils.Signature> {
    const kmsAddress = await this.signer.getAddress();
    if (from === undefined || from.toLowerCase() === kmsAddress.toLowerCase()) {
      return this.signer.signDigest(digest);
    }
    const extraKey = this.extraKeys.get(from.toLowerCase());
    if (extraKey !== undefined) {
      return extraKey.signDigest(digest);
    }
    throw new Error(
      `${method} from ${from} but the KMS deployer is ${kmsAddress}` +
        (this.extraKeys.size > 0
          ? ` and ${from} is not among the ${this.extraKeys.size} configured kmsExtraAccounts`
          : `; no other local account exists`)
    );
  }

  private async getChainId(): Promise<number> {
    if (!this.chainIdPromise) {
      this.chainIdPromise = this._wrappedProvider
        .request({ method: "eth_chainId" })
        .then((id) => BigNumber.from(id as string).toNumber());
    }
    return this.chainIdPromise;
  }

  private async sendTransaction(txRequest: any): Promise<unknown> {
    const from: string = txRequest.from ?? (await this.signer.getAddress());

    const nonce =
      txRequest.nonce !== undefined
        ? BigNumber.from(txRequest.nonce).toNumber()
        : BigNumber.from(
            await this._wrappedProvider.request({
              method: "eth_getTransactionCount",
              params: [from, "pending"],
            })
          ).toNumber();

    if (txRequest.gas === undefined) {
      throw new Error("eth_sendTransaction reached the KMS signer without a gas limit");
    }

    const tx: utils.UnsignedTransaction = {
      to: txRequest.to,
      data: txRequest.data,
      value: txRequest.value !== undefined ? BigNumber.from(txRequest.value) : undefined,
      gasLimit: BigNumber.from(txRequest.gas),
      nonce,
      chainId: await this.getChainId(),
    };

    if (txRequest.maxFeePerGas !== undefined || txRequest.maxPriorityFeePerGas !== undefined) {
      tx.type = 2;
      tx.maxFeePerGas = BigNumber.from(txRequest.maxFeePerGas ?? 0);
      tx.maxPriorityFeePerGas = BigNumber.from(txRequest.maxPriorityFeePerGas ?? 0);
      if (txRequest.accessList !== undefined) {
        tx.accessList = txRequest.accessList;
      }
    } else if (txRequest.gasPrice !== undefined) {
      tx.gasPrice = BigNumber.from(txRequest.gasPrice);
    } else {
      throw new Error("eth_sendTransaction reached the KMS signer without gas price fields");
    }

    const digest = utils.keccak256(utils.serializeTransaction(tx));
    const signature = await this.signatureFor(from, digest, "eth_sendTransaction");
    const raw = utils.serializeTransaction(tx, signature);

    return this._wrappedProvider.request({ method: "eth_sendRawTransaction", params: [raw] });
  }

  private async signMessage(address: string, data: string): Promise<string> {
    const digest = utils.hashMessage(utils.arrayify(data));
    return utils.joinSignature(await this.signatureFor(address, digest, "eth_sign/personal_sign"));
  }

  private async signTypedData(address: string, payload: string | object): Promise<string> {
    const typedData = typeof payload === "string" ? JSON.parse(payload) : payload;
    // ethers derives EIP712Domain from `domain`; it must not stay in types.
    const { EIP712Domain: _removed, ...types } = typedData.types;
    const digest = utils._TypedDataEncoder.hash(typedData.domain, types, typedData.message);
    return utils.joinSignature(await this.signatureFor(address, digest, "eth_signTypedData_v4"));
  }
}

extendProvider(async (provider, config, networkName) => {
  const networkConfig = config.networks[networkName] as HttpNetworkConfig;
  if (!networkConfig.kmsKeyId) {
    return provider;
  }
  // a configured accounts array would install LocalAccountsProvider on top of
  // this wrapper and shadow the KMS deployer — local keys next to KMS must go
  // through kmsExtraAccounts instead, which keeps the KMS address at index 0.
  if (Array.isArray(networkConfig.accounts) && networkConfig.accounts.length > 0) {
    throw new Error(
      `network ${networkName}: kmsKeyId and an accounts array are mutually exclusive — use kmsExtraAccounts for local keys that should remain usable next to the KMS deployer`
    );
  }
  return new KmsDeployerProvider(
    provider,
    new KmsEthSigner({ keyId: networkConfig.kmsKeyId, expectedAddress: networkConfig.kmsExpectedDeployer }),
    networkConfig.kmsExtraAccounts
  );
});
