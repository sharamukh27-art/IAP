import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import hre from "hardhat";

async function main() {
  const deploymentPath = process.env.AUDIT_DEPLOYMENT_FILE;
  const signingKeyPath = process.env.AUDIT_SIGNING_KEY_FILE;
  if (!deploymentPath || !signingKeyPath) {
    throw new Error("Set temporary audit deployment and signing-key paths.");
  }

  const { ethers } = await hre.network.create();
  const [
    admin,
    manufacturer,
    researcher,
    reviewer1,
    reviewer2,
    reviewer3,
    maintainer,
    unauthorized,
  ] = await ethers.getSigners();
  const Factory = await ethers.getContractFactory("InheritanceGovernance");
  const governance = await Factory.deploy(
    manufacturer.address,
    researcher.address,
    [reviewer1.address, reviewer2.address, reviewer3.address],
  );
  await governance.waitForDeployment();

  const signingKeys = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  fs.mkdirSync(path.dirname(signingKeyPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(signingKeyPath, signingKeys.privateKey, { mode: 0o600, flag: "wx" });
  const deployment = {
    chain_id: Number((await ethers.provider.getNetwork()).chainId),
    rpc_url: "http://127.0.0.1:8545",
    contract_address: await governance.getAddress(),
    deployer: admin.address,
    actors: {
      administrator: admin.address,
      manufacturer: manufacturer.address,
      researcher: researcher.address,
      reviewers: [reviewer1.address, reviewer2.address, reviewer3.address],
      maintainer: maintainer.address,
      unauthorized: unauthorized.address,
    },
    policy: { reviewers: 3, approvalsRequired: 2, challengePeriodSeconds: 60 },
    devices_registered: [],
    community_signing_public_key: signingKeys.publicKey,
    abi: Factory.interface.fragments.map((fragment) =>
      JSON.parse(fragment.format("json")),
    ),
  };
  fs.mkdirSync(path.dirname(deploymentPath), { recursive: true });
  fs.writeFileSync(deploymentPath, `${JSON.stringify(deployment, null, 2)}\n`, {
    mode: 0o600,
    flag: "wx",
  });
  console.log(`Temporary audit deployment written to ${deploymentPath}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
