import { expect } from "chai";
import hre from "hardhat";

const { ethers, provider } = await hre.network.create();
const DEVICE = {
  id: "CAM-B-002",
  manufacturer: "Aster Devices",
  model: "Aster View S",
  revision: "1.1",
  version: "2.0.8",
  firmwareHash: ethers.keccak256(ethers.toUtf8Bytes("firmware bytes sha256 placeholder")),
  supportEnd: 1_800_000_000,
  policyHash: ethers.keccak256(ethers.toUtf8Bytes("policy")),
};

async function expectRevert(transaction, reason) {
  let message = "";
  try {
    await transaction;
  } catch (error) {
    message = error instanceof Error ? error.message : String(error);
  }
  expect(message).to.include(reason);
}

async function expectEvent(transaction, contract, eventName) {
  const transactionResponse = await transaction;
  const receipt = await transactionResponse.wait();
  const eventNames = receipt.logs.flatMap((log) => {
    try {
      const parsed = contract.interface.parseLog(log);
      return parsed ? [parsed.name] : [];
    } catch {
      return [];
    }
  });
  expect(eventNames).to.include(eventName);
}

describe("InheritanceGovernance", function () {
  async function setup() {
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
    await governance.setManufacturerAccount(DEVICE.manufacturer, manufacturer.address);
    await governance.connect(manufacturer).registerDevice(
      DEVICE.id,
      DEVICE.manufacturer,
      DEVICE.model,
      DEVICE.revision,
      DEVICE.version,
      DEVICE.firmwareHash,
      DEVICE.supportEnd,
      DEVICE.policyHash,
      [reviewer1.address, reviewer2.address, reviewer3.address],
    );
    return {
      governance,
      admin,
      manufacturer,
      researcher,
      reviewer1,
      reviewer2,
      reviewer3,
      maintainer,
      unauthorized,
    };
  }

  async function authorizeOrphan(governance, reviewer1, reviewer2) {
    const evidenceHash = ethers.keccak256(ethers.toUtf8Bytes("phase2 evidence"));
    await governance.proposeOrphanDecision(DEVICE.id, true, evidenceHash);
    await governance.connect(reviewer1).voteOrphanDecision(DEVICE.id, true);
    await governance.connect(reviewer2).voteOrphanDecision(DEVICE.id, true);
    await provider.send("evm_increaseTime", [61]);
    await provider.send("evm_mine", []);
    await governance.finalizeOrphanDecision(DEVICE.id);
  }

  it("registers identity, firmware, support date, policy and 3-of-2 reviewer policy", async function () {
    const { governance, manufacturer, reviewer1 } = await setup();
    const device = await governance.getDevice(DEVICE.id);
    expect(device.exists).to.equal(true);
    expect(device.firmwareHash).to.equal(DEVICE.firmwareHash);
    expect(device.supportEndDate).to.equal(DEVICE.supportEnd);
    expect(await governance.getDeviceReviewers(DEVICE.id)).to.have.length(3);
    await expectRevert(
      governance.connect(reviewer1).recordSupportEndDate(DEVICE.id, 1_900_000_000),
      "manufacturer/admin only",
    );
    await expectEvent(
      governance.connect(manufacturer).recordSupportEndDate(DEVICE.id, 1_900_000_000),
      governance,
      "SupportEndDateRecorded",
    );
  });

  it("restricts administrator role changes and exercises device read helpers", async function () {
    const {
      governance,
      admin,
      manufacturer,
      reviewer1,
      reviewer2,
      researcher,
      unauthorized,
    } = await setup();
    const [, , , , , , , , newAccount] = await ethers.getSigners();

    expect(await governance.manufacturers(manufacturer.address)).to.equal(true);
    expect(await governance.researchers(researcher.address)).to.equal(true);
    expect(await governance.reviewers(reviewer1.address)).to.equal(true);
    expect(await governance.getDevicePatchIds(DEVICE.id)).to.deep.equal([]);
    await expectRevert(governance.getDevice("missing-device"), "unknown device");
    await expectRevert(governance.getDeviceReviewers("missing-device"), "unknown device");
    await expectRevert(governance.getDevicePatchIds("missing-device"), "unknown device");

    await expectRevert(
      governance.connect(unauthorized).setManufacturer(newAccount.address, true),
      "administrator only",
    );
    await expectRevert(
      governance.connect(unauthorized).setResearcher(newAccount.address, true),
      "administrator only",
    );
    await expectRevert(
      governance.connect(unauthorized).setReviewer(newAccount.address, true),
      "administrator only",
    );
    await expectRevert(
      governance.setManufacturer(ethers.ZeroAddress, true),
      "invalid account",
    );

    await governance.setManufacturer(newAccount.address, true);
    await governance.setResearcher(newAccount.address, true);
    await governance.setReviewer(newAccount.address, true);
    expect(await governance.manufacturers(newAccount.address)).to.equal(true);
    expect(await governance.researchers(newAccount.address)).to.equal(true);
    expect(await governance.reviewers(newAccount.address)).to.equal(true);
    await governance.setManufacturer(newAccount.address, false);
    await governance.setResearcher(newAccount.address, false);
    await governance.setReviewer(newAccount.address, false);
    expect(await governance.manufacturers(newAccount.address)).to.equal(false);
    expect(await governance.researchers(newAccount.address)).to.equal(false);
    expect(await governance.reviewers(newAccount.address)).to.equal(false);

    await expectRevert(
      governance.connect(unauthorized).proposeMaintainer(DEVICE.id, newAccount.address),
      "administrator only",
    );
    await governance.proposeMaintainer(DEVICE.id, newAccount.address);
    await governance.connect(reviewer1).voteMaintainer(DEVICE.id, newAccount.address, false);
    await governance.connect(reviewer2).voteMaintainer(DEVICE.id, newAccount.address, false);
    expect(await governance.maintainers(DEVICE.id, newAccount.address)).to.equal(false);
    expect(await governance.getDevicePatchIds(DEVICE.id)).to.deep.equal([]);
    expect((await governance.getDevice(DEVICE.id)).exists).to.equal(true);
    expect(admin.address).to.equal(await governance.administrator());
  });

  it("binds manufacturer support updates and registration to configured accounts", async function () {
    const { governance, manufacturer, admin, unauthorized } = await setup();
    const [, , , , , , , , secondManufacturer] = await ethers.getSigners();
    const assignedReviewers = await governance.getDeviceReviewers(DEVICE.id);
    await governance.setManufacturer(secondManufacturer.address, true);
    await governance.setManufacturerAccount("Other Devices", secondManufacturer.address);

    await expectRevert(
      governance.connect(secondManufacturer).recordSupportEndDate(DEVICE.id, 1_900_000_000),
      "manufacturer/admin only",
    );
    await expectRevert(
      governance.connect(unauthorized).registerDevice(
        "OTHER-DEVICE",
        "Other Devices",
        DEVICE.model,
        DEVICE.revision,
        DEVICE.version,
        DEVICE.firmwareHash,
        DEVICE.supportEnd,
        DEVICE.policyHash,
        Array.from(assignedReviewers),
      ),
      "manufacturer/admin only",
    );

    await governance.connect(secondManufacturer).registerDevice(
      "OTHER-DEVICE",
      "Other Devices",
      DEVICE.model,
      DEVICE.revision,
      DEVICE.version,
      DEVICE.firmwareHash,
      DEVICE.supportEnd,
      DEVICE.policyHash,
      Array.from(assignedReviewers),
    );
    await expectRevert(
      governance.connect(manufacturer).recordSupportEndDate("OTHER-DEVICE", 1_900_000_000),
      "manufacturer/admin only",
    );
    await expectEvent(
      governance.connect(secondManufacturer).recordSupportEndDate(
        "OTHER-DEVICE",
        1_900_000_000,
      ),
      governance,
      "SupportEndDateRecorded",
    );
    await expectEvent(
      governance.connect(admin).recordSupportEndDate(DEVICE.id, 1_900_000_000),
      governance,
      "SupportEndDateRecorded",
    );
  });

  it("requires two assigned reviewer votes and a challenge before orphan verification", async function () {
    const { governance, reviewer1, reviewer2, unauthorized } = await setup();
    await governance.proposeOrphanDecision(
      DEVICE.id,
      true,
      ethers.keccak256(ethers.toUtf8Bytes("evidence")),
    );
    await expectRevert(
      governance.connect(unauthorized).voteOrphanDecision(DEVICE.id, true),
      "assigned reviewer only",
    );
    await governance.connect(reviewer1).voteOrphanDecision(DEVICE.id, true);
    await expectRevert(
      governance.finalizeOrphanDecision(DEVICE.id),
      "challenge period active",
    );
    await governance.connect(reviewer2).voteOrphanDecision(DEVICE.id, true);
    await provider.send("evm_increaseTime", [61]);
    await provider.send("evm_mine", []);
    await governance.finalizeOrphanDecision(DEVICE.id);
    expect((await governance.getDevice(DEVICE.id)).orphanVerified).to.equal(true);
  });

  it("uses a unique proposal nonce so later verification rounds can reuse reviewers", async function () {
    const { governance, reviewer1, reviewer2 } = await setup();
    const evidenceHash = ethers.keccak256(ethers.toUtf8Bytes("first evidence"));
    await governance.proposeOrphanDecision(DEVICE.id, true, evidenceHash);
    await governance.connect(reviewer1).voteOrphanDecision(DEVICE.id, true);
    await expectRevert(
      governance.connect(reviewer1).voteOrphanDecision(DEVICE.id, true),
      "reviewer already voted",
    );
    await governance.connect(reviewer2).voteOrphanDecision(DEVICE.id, true);
    await provider.send("evm_increaseTime", [61]);
    await provider.send("evm_mine", []);
    await governance.finalizeOrphanDecision(DEVICE.id);

    await governance.proposeOrphanDecision(
      DEVICE.id,
      false,
      ethers.keccak256(ethers.toUtf8Bytes("revised evidence")),
    );
    await governance.connect(reviewer1).voteOrphanDecision(DEVICE.id, true);
    await governance.connect(reviewer2).voteOrphanDecision(DEVICE.id, true);
    await provider.send("evm_increaseTime", [61]);
    await provider.send("evm_mine", []);
    await governance.finalizeOrphanDecision(DEVICE.id);
    expect((await governance.getDevice(DEVICE.id)).orphanVerified).to.equal(false);
  });

  it("revokes recovery authorization when orphan verification is reversed", async function () {
    const { governance, reviewer1, reviewer2, maintainer } = await setup();
    await authorizeOrphan(governance, reviewer1, reviewer2);
    const patchHash = ethers.keccak256(ethers.toUtf8Bytes("approved patch"));
    await governance.submitPatch(DEVICE.id, "PATCH-REVOKE", patchHash, true);
    await governance.connect(reviewer1).votePatch("PATCH-REVOKE", true);
    await governance.connect(reviewer2).votePatch("PATCH-REVOKE", true);
    await governance.proposeMaintainer(DEVICE.id, maintainer.address);
    await governance.connect(reviewer1).voteMaintainer(DEVICE.id, maintainer.address, true);
    await governance.connect(reviewer2).voteMaintainer(DEVICE.id, maintainer.address, true);
    await governance.authorizeRecovery(DEVICE.id, "PATCH-REVOKE");

    await governance.proposeOrphanDecision(
      DEVICE.id,
      false,
      ethers.keccak256(ethers.toUtf8Bytes("disputed evidence")),
    );
    await governance.connect(reviewer1).voteOrphanDecision(DEVICE.id, true);
    await governance.connect(reviewer2).voteOrphanDecision(DEVICE.id, true);
    await provider.send("evm_increaseTime", [61]);
    await provider.send("evm_mine", []);
    await governance.finalizeOrphanDecision(DEVICE.id);

    expect((await governance.getDevice(DEVICE.id)).orphanVerified).to.equal(false);
    expect(await governance.recoveryPatch(DEVICE.id)).to.equal("");
    await expectRevert(
      governance.connect(maintainer).recordFirmwareRelease(
        DEVICE.id,
        "PATCH-REVOKE",
        "2.0.9",
        patchHash,
      ),
      "orphan verification required",
    );
  });

  it("rejects unauthorized patch approval and blocks votes when automated tests failed", async function () {
    const { governance, researcher, reviewer1, reviewer2, unauthorized } = await setup();
    await authorizeOrphan(governance, reviewer1, reviewer2);
    const patchHash = ethers.keccak256(ethers.toUtf8Bytes("patch hash"));
    await expectRevert(
      governance.connect(unauthorized).submitPatch(
        DEVICE.id,
        "PATCH-UNAUTHORIZED",
        patchHash,
        true,
      ),
      "researcher/admin only",
    );
    await governance.connect(researcher).submitPatch(
      DEVICE.id,
      "PATCH-RESEARCHER",
      patchHash,
      true,
    );
    expect((await governance.patches("PATCH-RESEARCHER")).submitter).to.equal(
      researcher.address,
    );
    await governance.submitPatch(DEVICE.id, "PATCH-FAIL", patchHash, false);
    await expectRevert(
      governance.connect(unauthorized).votePatch("PATCH-FAIL", true),
      "automated tests must pass",
    );
    await governance.submitPatch(DEVICE.id, "PATCH-OK", patchHash, true);
    await expectRevert(
      governance.connect(unauthorized).votePatch("PATCH-OK", true),
      "reviewer role required",
    );
    await governance.connect(reviewer1).votePatch("PATCH-OK", true);
    expect((await governance.patches("PATCH-OK")).approved).to.equal(false);
    await governance.connect(reviewer2).votePatch("PATCH-OK", true);
    expect((await governance.patches("PATCH-OK")).approved).to.equal(true);
  });

  it("requires approved patch, authorized maintainer, and exact file hash for release", async function () {
    const { governance, admin, reviewer1, reviewer2, maintainer, unauthorized } =
      await setup();
    await authorizeOrphan(governance, reviewer1, reviewer2);
    const patchHash = ethers.keccak256(ethers.toUtf8Bytes("actual file sha256"));
    await governance.submitPatch(DEVICE.id, "PATCH-1", patchHash, true);
    await governance.connect(reviewer1).votePatch("PATCH-1", true);
    await governance.connect(reviewer2).votePatch("PATCH-1", true);
    await governance.authorizeRecovery(DEVICE.id, "PATCH-1");

    await expectRevert(
      governance.connect(unauthorized).recordFirmwareRelease(
        DEVICE.id,
        "PATCH-1",
        "2.0.9",
        patchHash,
      ),
      "authorized community maintainer only",
    );
    await governance.proposeMaintainer(DEVICE.id, maintainer.address);
    await governance.connect(reviewer1).voteMaintainer(DEVICE.id, maintainer.address, true);
    await governance.connect(reviewer2).voteMaintainer(DEVICE.id, maintainer.address, true);

    await expectRevert(
      governance.connect(maintainer).recordFirmwareRelease(
        DEVICE.id,
        "PATCH-1",
        "2.0.9",
        ethers.keccak256(ethers.toUtf8Bytes("tampered")),
      ),
      "firmware hash mismatch",
    );
    await expectEvent(
      governance.connect(maintainer).recordFirmwareRelease(
        DEVICE.id,
        "PATCH-1",
        "2.0.9",
        patchHash,
      ),
      governance,
      "FirmwareReleased",
    );
    expect((await governance.getDevice(DEVICE.id)).firmwareVersion).to.equal("2.0.9");

    await governance.pause();
    await expectRevert(governance.connect(unauthorized).unpause(), "administrator only");
    await expectRevert(
      governance.submitPatch(DEVICE.id, "PATCH-PAUSED", patchHash, true),
      "protocol paused",
    );
    await expectRevert(
      governance.connect(unauthorized).revokeMaintainer(DEVICE.id, maintainer.address),
      "administrator only",
    );
    await governance.connect(admin).revokeMaintainer(DEVICE.id, maintainer.address);
    expect(await governance.maintainers(DEVICE.id, maintainer.address)).to.equal(false);
    await governance.unpause();
  });

  it("allows emergency recovery revocation while paused and emits tamper-evident events", async function () {
    const { governance, reviewer1, reviewer2, maintainer } = await setup();
    await authorizeOrphan(governance, reviewer1, reviewer2);
    const patchHash = ethers.keccak256(ethers.toUtf8Bytes("patch"));
    await governance.submitPatch(DEVICE.id, "PATCH-2", patchHash, true);
    await governance.connect(reviewer1).votePatch("PATCH-2", true);
    await governance.connect(reviewer2).votePatch("PATCH-2", true);
    await governance.authorizeRecovery(DEVICE.id, "PATCH-2");
    await governance.proposeMaintainer(DEVICE.id, maintainer.address);
    await governance.connect(reviewer1).voteMaintainer(DEVICE.id, maintainer.address, true);
    await governance.connect(reviewer2).voteMaintainer(DEVICE.id, maintainer.address, true);
    await governance.pause();
    await expectEvent(governance.revokeRecovery(DEVICE.id), governance, "RecoveryRevoked");
    const events = await governance.queryFilter(governance.filters.PatchSubmitted());
    expect(events).to.have.length(1);
    expect(events[0].transactionHash).to.match(/^0x[0-9a-f]{64}$/i);
  });
});
