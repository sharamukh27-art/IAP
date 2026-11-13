import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import hre from "hardhat";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const reviewersPolicy = {
  reviewers: 3,
  approvalsRequired: 2,
  challengePeriodSeconds: 60,
  conditions: [
    "orphanVerified",
    "automatedPatchTestsPassed",
    "twoDistinctReviewerApprovals",
    "uploadedFileSha256Matches",
    "rollbackAvailable",
    "maintainerAuthorizedForDevice",
  ],
  disputes: "reviewer rejection blocks threshold; administrator may revoke maintainer/recovery authorization",
};

function hashLabel(value) {
  return `0x${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function epoch(date) {
  return Math.floor(new Date(`${date}T00:00:00Z`).getTime() / 1000);
}

async function main() {
  const { ethers } = await hre.network.create();
  const [admin, manufacturer, researcher, reviewer1, reviewer2, reviewer3, maintainer] =
    await ethers.getSigners();
  const Governance = await ethers.getContractFactory("InheritanceGovernance");
  const governance = await Governance.deploy(
    manufacturer.address,
    researcher.address,
    [reviewer1.address, reviewer2.address, reviewer3.address],
  );
  await governance.waitForDeployment();

  const reviewerAddresses = [reviewer1.address, reviewer2.address, reviewer3.address];
  const devices = [
    {
      id: "CAM-A-001", manufacturer: "Northstar Home", model: "NS-Cam 2K", revision: "R2",
      version: "3.4.1", support: "2027-03-15",
    },
    {
      id: "CAM-B-002", manufacturer: "Aster Devices", model: "Aster View S", revision: "1.1",
      version: "2.0.8", support: "2024-08-20",
    },
    {
      id: "LOCK-003", manufacturer: "Hearth & Key", model: "HK SecureBolt", revision: "B3",
      version: "1.8.2", support: "2026-12-01",
    },
    {
      id: "BABY-004", manufacturer: "Lullaby Labs", model: "Lullaby Monitor One", revision: "A2",
      version: "1.3.0", support: "2022-02-10",
    },
    {
      id: "THERMO-005", manufacturer: "Evergreen Climate", model: "Evergreen T-Connect", revision: "C1",
      version: "5.2.0", support: "2025-10-01",
    },
    {
      id: "GW-006", manufacturer: "Northstar Home", model: "NS Hub 4", revision: "R4",
      version: "4.7.3", support: "2029-06-08",
    },
    {
      id: "AST-CAM-003", manufacturer: "Aster Devices", model: "Aster View S", revision: "1.1",
      version: "2.0.6", support: "2024-03-12",
    },
    {
      id: "AST-CAM-004", manufacturer: "Aster Devices", model: "Aster View S", revision: "1.1",
      version: "2.0.5", support: "2023-11-06",
    },
  ];

  for (const manufacturerName of new Set(devices.map((device) => device.manufacturer))) {
    await (
      await governance.setManufacturerAccount(manufacturerName, manufacturer.address)
    ).wait();
  }

  for (const device of devices) {
    const policyHash = hashLabel(JSON.stringify(reviewersPolicy));
    const firmwareHash = hashLabel(
      `${device.id}:${device.version}:simulated-firmware`,
    );
    const tx = await governance.connect(manufacturer).registerDevice(
      device.id,
      device.manufacturer,
      device.model,
      device.revision,
      device.version,
      firmwareHash,
      epoch(device.support),
      policyHash,
      reviewerAddresses,
    );
    await tx.wait();
    const maintainerProposal = await governance.proposeMaintainer(
      device.id,
      maintainer.address,
    );
    await maintainerProposal.wait();
    await (await governance.connect(reviewer1).voteMaintainer(
      device.id,
      maintainer.address,
      true,
    )).wait();
    await (await governance.connect(reviewer2).voteMaintainer(
      device.id,
      maintainer.address,
      true,
    )).wait();
  }

  const deployment = {
    chain_id: Number((await ethers.provider.getNetwork()).chainId),
    rpc_url: process.env.BLOCKCHAIN_RPC_URL || "http://127.0.0.1:8545",
    contract_address: await governance.getAddress(),
    deployer: admin.address,
    actors: {
      administrator: admin.address,
      manufacturer: manufacturer.address,
      researcher: researcher.address,
      reviewers: reviewerAddresses,
      maintainer: maintainer.address,
      unauthorized: (await ethers.getSigners())[8].address,
    },
    policy: reviewersPolicy,
    devices_registered: devices.map((device) => device.id),
    generated_at: new Date().toISOString(),
    abi: Governance.interface.fragments.map((fragment) =>
      JSON.parse(fragment.format("json")),
    ),
  };
  const keyDirectory = path.resolve(__dirname, "../../backend/storage/keys");
  fs.mkdirSync(keyDirectory, { recursive: true, mode: 0o700 });
  const signingKeyPath = path.join(keyDirectory, "community-maintainer-ed25519.pem");
  if (!fs.existsSync(signingKeyPath)) {
    const signingKeys = crypto.generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    fs.writeFileSync(signingKeyPath, signingKeys.privateKey, { mode: 0o600, flag: "wx" });
  }
  const signingPrivateKey = crypto.createPrivateKey(fs.readFileSync(signingKeyPath));
  deployment.community_signing_public_key = crypto
    .createPublicKey(signingPrivateKey)
    .export({ type: "spki", format: "pem" })
    .toString();
  const output = path.resolve(__dirname, "../../backend/app/blockchain_deployment.json");
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, `${JSON.stringify(deployment, null, 2)}\n`);
  console.log(`Governance contract deployed at ${deployment.contract_address}`);
  console.log(`Registered ${devices.length} virtual devices; deployment metadata: ${output}`);
  console.log("Local test accounts are unlocked Hardhat accounts; no private key is exported.");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
