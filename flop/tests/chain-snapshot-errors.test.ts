// SPDX-License-Identifier: Apache-2.0
// Regression tests for the chain-layer error handling findings (deep-hunt-2
// CH batch): snapshot() must fail closed with clean "flop:" errors on
// malformed escrow records and must validate its own outputs; open() must
// keep the txHash on a malformed EscrowOpened id; connectFlopRail must not
// surface a bare WsProvider ErrorEvent.
import { describe, expect, it, vi } from "vitest";

const connection = vi.hoisted(() => ({
  disconnect: vi.fn(async () => {}),
}));
vi.mock("@polkadot/api", () => ({
  WsProvider: class {
    connect = vi.fn(async () => {
      // What a real WsProvider rejects with: a bare ErrorEvent, not an Error.
      throw { type: "error", message: "" };
    });
  },
  ApiPromise: class {
    isReadyOrError = new Promise<void>(() => {});
    disconnect = connection.disconnect;
  },
}));
import {
  connectFlopRail,
  FlopTransactionError,
  PolkadotFlopChain,
} from "../src/chain.js";
import type { KeyringPair } from "@polkadot/keyring/types";

const H = `0x${"aa".repeat(32)}`;
const ID = `0x${"ab".repeat(32)}`;
const TXH = `0x${"dd".repeat(32)}`;
const signer = {
  type: "ed25519",
  publicKey: new Uint8Array(32).fill(7),
} as unknown as KeyringPair;

function str(v: unknown) {
  return { toString: () => String(v), toHex: () => String(v), toJSON: () => v };
}
function validRaw(overrides: Record<string, unknown> = {}) {
  return {
    id: ID,
    funder: H,
    payee: H,
    policy: { combinator: { and: null }, clauses: [{ hash: H }] },
    status: "Open",
    ...overrides,
  };
}
function validFields(overrides: Record<string, unknown> = {}) {
  return {
    amount: str("1000"),
    deadline: str("200"),
    createdBlock: str("90"),
    ...overrides,
  };
}

/** Fake ApiPromise-shaped object. `escrow` null means isSome false. */
function fakeApi(opts: Record<string, any> = {}) {
  const o = {
    headerNumbers: [100, 100],
    timestamp: "1700000000000",
    prefixJson: [90, H],
    escrow: { raw: validRaw(), fields: validFields() },
    createTypeThrows: false,
    throwOn: {} as Record<string, Error>,
    txResult: undefined as any,
    ...opts,
  };
  let headerCalls = 0;
  const view = {
    query: {
      timestamp: {
        now: async () => {
          if (o.throwOn.now) throw o.throwOn.now;
          return str(o.timestamp);
        },
      },
      aleph: {
        lastFinalized: async () => {
          if (o.throwOn.lastFinalized) throw o.throwOn.lastFinalized;
          return { toJSON: () => o.prefixJson };
        },
      },
      hasStation: {
        escrows: async (_id: string) => {
          if (o.throwOn.escrows) throw o.throwOn.escrows;
          if (o.escrow === null) return { isSome: false };
          return {
            isSome: true,
            unwrap: () => ({
              toJSON: () => o.escrow.raw,
              get: (key: string) => o.escrow.fields[key],
            }),
          };
        },
      },
    },
  };
  const tx = {
    hash: { toHex: () => `0x${"cc".repeat(32)}` },
    signAndSend: vi.fn((_s: unknown, _o: unknown, cb: (r: unknown) => void) => {
      cb(o.txResult);
      return Promise.resolve(() => {});
    }),
  };
  const api: any = {
    tx: {
      hasStation: {
        openEscrow: vi.fn(() => tx),
        satisfyEscrow: vi.fn(() => tx),
        refundEscrow: vi.fn(() => tx),
      },
    },
    query: {
      hasStation: { escrows: vi.fn() },
      aleph: { lastFinalized: vi.fn() },
    },
    rpc: {
      chain: {
        getFinalizedHead: vi.fn(async () => {
          if (o.throwOn.getFinalizedHead) throw o.throwOn.getFinalizedHead;
          return { toHex: () => H };
        }),
        getHeader: vi.fn(async () => {
          if (o.throwOn.getHeader) throw o.throwOn.getHeader;
          return { number: { toString: () => String(o.headerNumbers[headerCalls++ % 2]) } };
        }),
        getBlockHash: vi.fn(async () => {
          if (o.throwOn.getBlockHash) throw o.throwOn.getBlockHash;
          return { toHex: () => H };
        }),
      },
    },
    at: vi.fn(async () => {
      if (o.throwOn.at) throw o.throwOn.at;
      return view;
    }),
    registry: {
      createType: vi.fn((_type: string, v: unknown) => {
        if (o.createTypeThrows) throw new Error("mock registry: invalid AccountId32");
        return { toHex: () => v };
      }),
    },
  };
  return { api, tx };
}

function successResult(events: unknown[], extra: Record<string, unknown> = {}) {
  return {
    status: {
      isFinalized: true,
      isInvalid: false,
      isDropped: false,
      isUsurped: false,
      isFinalityTimeout: false,
    },
    events,
    dispatchError: undefined,
    txHash: { toHex: () => TXH },
    ...extra,
  };
}
const successEvent = { event: { section: "system", method: "ExtrinsicSuccess", data: [] } };
const openedEvent = (id: string) => ({
  event: { section: "hasStation", method: "EscrowOpened", data: [{ toString: () => id }] },
});

describe("snapshot() fails closed with flop: errors", () => {
  it("converts transport failures instead of leaking raw errors", async () => {
    for (const key of ["getHeader", "getFinalizedHead", "getBlockHash", "at", "now", "lastFinalized", "escrows"] as const) {
      const { api } = fakeApi({ throwOn: { [key]: new Error("mock rpc boom") }, escrow: null });
      const chain = new PolkadotFlopChain(api);
      // Pass an escrow id so the escrows query actually runs too.
      await expect(chain.snapshot(ID, H)).rejects.toThrow("flop: failed to read finalized chain state");
    }
  });

  it("rejects malformed escrow records instead of throwing raw TypeErrors", async () => {
    const cases: Array<[string, any]> = [
      ["policy null", { escrow: { raw: validRaw({ policy: null }), fields: validFields() } }],
      ["policy missing", { escrow: { raw: (() => { const r = validRaw(); delete (r as any).policy; return r; })(), fields: validFields() } }],
      ["clauses null", { escrow: { raw: validRaw({ policy: { combinator: { and: null }, clauses: null } }), fields: validFields() } }],
      ["clauses a string", { escrow: { raw: validRaw({ policy: { combinator: { and: null }, clauses: "nope" } }), fields: validFields() } }],
      ["clause null", { escrow: { raw: validRaw({ policy: { combinator: { and: null }, clauses: [null] } }), fields: validFields() } }],
      ["record.toJSON() null", { escrow: { raw: null, fields: validFields() } }],
      ["amount field missing", { escrow: { raw: validRaw(), fields: { ...validFields(), amount: undefined } } }],
      ["deadline field missing", { escrow: { raw: validRaw(), fields: { ...validFields(), deadline: undefined } } }],
      ["registry createType throws", { createTypeThrows: true }],
    ];
    for (const [label, opts] of cases) {
      const { api } = fakeApi(opts);
      const chain = new PolkadotFlopChain(api);
      await expect(chain.snapshot(ID, H), label).rejects.toThrow(/^flop: /);
    }
  });

  it("validates its own outputs", async () => {
    // Finalized height above the snapshot height.
    {
      const { api } = fakeApi({ prefixJson: [9999, 0] });
      await expect(new PolkadotFlopChain(api).snapshot()).rejects.toThrow(
        "flop: malformed finalized snapshot",
      );
    }
    // Non-positive timestamp.
    {
      const { api } = fakeApi({ timestamp: "0" });
      await expect(new PolkadotFlopChain(api).snapshot()).rejects.toThrow(
        "flop: malformed finalized snapshot",
      );
    }
    // Non-canonical amounts.
    for (const amount of ["abc", "-5", "0", "", "1e3"]) {
      const { api } = fakeApi({ escrow: { raw: validRaw(), fields: validFields({ amount: str(amount) }) } });
      await expect(new PolkadotFlopChain(api).snapshot(ID, H)).rejects.toThrow(
        "flop: malformed escrow amount",
      );
    }
    // Missing id / status no longer become the literal string "undefined".
    {
      const raw = validRaw(); delete (raw as any).id;
      const { api } = fakeApi({ escrow: { raw, fields: validFields() } });
      await expect(new PolkadotFlopChain(api).snapshot(ID, H)).rejects.toThrow(
        "flop: malformed escrow id",
      );
    }
    {
      const raw = validRaw(); delete (raw as any).status;
      const { api } = fakeApi({ escrow: { raw, fields: validFields() } });
      await expect(new PolkadotFlopChain(api).snapshot(ID, H)).rejects.toThrow(
        "flop: malformed escrow status",
      );
    }
  });

  it("still resolves a well-formed snapshot", async () => {
    const { api } = fakeApi();
    const s = await new PolkadotFlopChain(api).snapshot(ID, H);
    expect(s.number).toBe(100);
    expect(s.finalizedNumber).toBe(90);
    expect(s.escrow?.amount).toBe("1000");
    expect(s.escrow?.id).toBe(ID);
  });
});

describe("open() keeps the txHash on malformed event data", () => {
  const openReq = { payee: H, amount: "1000", policy: { combinator: "And", clauses: [] }, deadlineBlocks: 10 };
  it.each([
    ["empty data array", []],
    ["missing data", undefined],
    ["null datum", [null]],
    ["undefined datum", [undefined]],
  ])("%s throws FlopTransactionError with the txHash", async (_label, data) => {
    const result = successResult([successEvent, { event: { section: "hasStation", method: "EscrowOpened", data } }]);
    const { api } = fakeApi({ txResult: result });
    const chain = new PolkadotFlopChain(api, signer);
    const error = await chain.open(openReq as never).catch((e) => e);
    expect(error).toBeInstanceOf(FlopTransactionError);
    expect(error.message).toBe("flop: malformed EscrowOpened id");
    expect(error.txHash).toBe(TXH);
  });

  it("malformed id on a result without txHash still throws FlopTransactionError", async () => {
    const result = successResult([successEvent, openedEvent("0x1234")], { txHash: undefined });
    const { api } = fakeApi({ txResult: result });
    const chain = new PolkadotFlopChain(api, signer);
    const error = await chain.open(openReq as never).catch((e) => e);
    expect(error).toBeInstanceOf(FlopTransactionError);
    expect(error.message).toBe("flop: malformed EscrowOpened id");
  });

  it("still resolves a well-formed open", async () => {
    const result = successResult([successEvent, openedEvent(ID)]);
    const { api } = fakeApi({ txResult: result });
    const id = await new PolkadotFlopChain(api, signer).open(openReq as never);
    expect(id).toBe(ID);
  });
});

describe("connectFlopRail() surfaces a flop: error on connection failure", () => {
  it("converts a bare provider rejection", async () => {
    await expect(connectFlopRail({ network: "devnet" } as never)).rejects.toThrow(
      "flop: failed to connect to the FLOP node",
    );
    expect(connection.disconnect).toHaveBeenCalled();
  });
});
