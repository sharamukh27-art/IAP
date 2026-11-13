// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract InheritanceGovernance {
    uint8 public constant REQUIRED_APPROVALS = 2;
    uint8 public constant REVIEWER_COUNT = 3;
    uint64 public constant ORPHAN_CHALLENGE_PERIOD = 60;

    address public immutable administrator;
    bool public paused;

    struct Device {
        bool exists;
        bool orphanVerified;
        address manufacturerAccount;
        string manufacturer;
        string model;
        string hardwareRevision;
        string firmwareVersion;
        bytes32 firmwareHash;
        uint64 supportEndDate;
        bytes32 recoveryPolicyHash;
        uint64 registeredAt;
    }

    struct OrphanProposal {
        bool exists;
        bool decision;
        uint64 submittedAt;
        uint256 proposalId;
        bytes32 evidenceHash;
        uint8 approvals;
        uint8 rejections;
        bool finalized;
    }

    struct MaintainerProposal {
        bool exists;
        bool finalized;
        uint256 proposalId;
        uint8 approvals;
        uint8 rejections;
        uint64 proposedAt;
    }

    struct PatchRecord {
        bool exists;
        bool automatedTestsPassed;
        bool approved;
        bool reviewFinalized;
        bytes32 patchHash;
        uint8 approvals;
        uint8 rejections;
        address submitter;
    }

    mapping(address => bool) public manufacturers;
    mapping(string => address) public manufacturerAccounts;
    mapping(address => bool) public researchers;
    mapping(address => bool) public reviewers;
    mapping(string => Device) private devices;
    mapping(string => address[]) private deviceReviewers;
    mapping(string => mapping(address => bool)) public maintainers;
    mapping(string => mapping(address => MaintainerProposal)) public maintainerProposals;
    mapping(string => OrphanProposal) public orphanProposals;
    mapping(string => PatchRecord) public patches;
    mapping(string => string[]) private devicePatchIds;
    mapping(string => string) public recoveryPatch;
    uint256 private _proposalNonce;

    event DeviceRegistered(
        string deviceId,
        string manufacturer,
        string model,
        string hardwareRevision,
        string firmwareVersion,
        bytes32 firmwareHash,
        uint64 supportEndDate,
        bytes32 recoveryPolicyHash,
        uint64 timestamp
    );
    event FirmwareRecorded(
        string deviceId,
        string firmwareVersion,
        bytes32 firmwareHash,
        address indexed recordedBy,
        uint64 timestamp
    );
    event SupportEndDateRecorded(
        string deviceId,
        uint64 supportEndDate,
        address indexed recordedBy,
        uint64 timestamp
    );
    event OrphanDecisionProposed(
        string deviceId,
        bool decision,
        bytes32 evidenceHash,
        uint64 submittedAt
    );
    event OrphanDecisionVoted(
        string deviceId,
        address indexed reviewer,
        bool approval,
        uint64 timestamp
    );
    event OrphanDecisionFinalized(
        string deviceId,
        bool verified,
        uint8 approvals,
        uint8 rejections,
        uint64 timestamp
    );
    event MaintainerProposed(
        string deviceId,
        address indexed maintainer,
        uint64 timestamp
    );
    event MaintainerVoted(
        string deviceId,
        address indexed maintainer,
        address indexed reviewer,
        bool approval,
        uint64 timestamp
    );
    event MaintainerAuthorized(
        string deviceId,
        address indexed maintainer,
        uint64 timestamp
    );
    event MaintainerRevoked(
        string deviceId,
        address indexed maintainer,
        address indexed revokedBy,
        uint64 timestamp
    );
    event PatchSubmitted(
        string deviceId,
        string patchId,
        bytes32 patchHash,
        bool automatedTestsPassed,
        address indexed submitter,
        uint64 timestamp
    );
    event PatchApprovalVoted(
        string patchId,
        address indexed reviewer,
        bool approval,
        uint64 timestamp
    );
    event PatchApprovalFinalized(
        string patchId,
        bool approved,
        uint8 approvals,
        uint8 rejections,
        uint64 timestamp
    );
    event RecoveryAuthorized(
        string deviceId,
        string patchId,
        address indexed authorizedBy,
        uint64 timestamp
    );
    event FirmwareReleased(
        string deviceId,
        string patchId,
        string firmwareVersion,
        bytes32 firmwareHash,
        address indexed releasedBy,
        uint64 timestamp
    );
    event RecoveryRevoked(
        string deviceId,
        string patchId,
        address indexed revokedBy,
        uint64 timestamp
    );
    event EmergencyPause(bool paused, address indexed actor, uint64 timestamp);
    event ManufacturerAccountConfigured(
        string manufacturer,
        address indexed account,
        address indexed configuredBy,
        uint64 timestamp
    );

    modifier onlyAdministrator() {
        require(msg.sender == administrator, "administrator only");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "protocol paused");
        _;
    }

    modifier deviceExists(string calldata deviceId) {
        require(devices[deviceId].exists, "unknown device");
        _;
    }

    constructor(
        address manufacturer,
        address researcher,
        address[3] memory initialReviewers
    ) {
        require(manufacturer != address(0), "invalid manufacturer");
        require(researcher != address(0), "invalid researcher");
        administrator = msg.sender;
        manufacturers[manufacturer] = true;
        researchers[researcher] = true;
        for (uint256 i = 0; i < initialReviewers.length; i++) {
            require(initialReviewers[i] != address(0), "invalid reviewer");
            for (uint256 j = 0; j < i; j++) {
                require(initialReviewers[i] != initialReviewers[j], "duplicate reviewer");
            }
            reviewers[initialReviewers[i]] = true;
        }
    }

    function setManufacturer(address account, bool enabled) external onlyAdministrator {
        require(account != address(0), "invalid account");
        manufacturers[account] = enabled;
    }

    function setManufacturerAccount(
        string calldata manufacturerName,
        address account
    ) external onlyAdministrator {
        require(bytes(manufacturerName).length > 0, "manufacturer name required");
        require(account != address(0) && manufacturers[account], "invalid manufacturer account");
        manufacturerAccounts[manufacturerName] = account;
        emit ManufacturerAccountConfigured(
            manufacturerName,
            account,
            msg.sender,
            uint64(block.timestamp)
        );
    }

    function setResearcher(address account, bool enabled) external onlyAdministrator {
        require(account != address(0), "invalid account");
        researchers[account] = enabled;
    }

    function setReviewer(address account, bool enabled) external onlyAdministrator {
        require(account != address(0), "invalid account");
        reviewers[account] = enabled;
    }

    function registerDevice(
        string calldata deviceId,
        string calldata manufacturerName,
        string calldata model,
        string calldata hardwareRevision,
        string calldata firmwareVersion,
        bytes32 firmwareHash,
        uint64 supportEndDate,
        bytes32 recoveryPolicyHash,
        address[3] calldata assignedReviewers
    ) external whenNotPaused {
        require(
            msg.sender == administrator
                || (
                    manufacturers[msg.sender]
                        && manufacturerAccounts[manufacturerName] == msg.sender
                ),
            "manufacturer/admin only"
        );
        require(bytes(deviceId).length > 0 && !devices[deviceId].exists, "invalid or registered device");
        require(bytes(manufacturerName).length > 0 && bytes(model).length > 0, "missing device metadata");
        require(firmwareHash != bytes32(0), "firmware hash required");
        require(recoveryPolicyHash != bytes32(0), "recovery policy required");

        delete deviceReviewers[deviceId];
        for (uint256 i = 0; i < assignedReviewers.length; i++) {
            require(reviewers[assignedReviewers[i]], "assigned account is not a reviewer");
            for (uint256 j = 0; j < i; j++) {
                require(assignedReviewers[i] != assignedReviewers[j], "duplicate assigned reviewer");
            }
            deviceReviewers[deviceId].push(assignedReviewers[i]);
        }

        devices[deviceId] = Device({
            exists: true,
            orphanVerified: false,
            manufacturerAccount: manufacturerAccounts[manufacturerName],
            manufacturer: manufacturerName,
            model: model,
            hardwareRevision: hardwareRevision,
            firmwareVersion: firmwareVersion,
            firmwareHash: firmwareHash,
            supportEndDate: supportEndDate,
            recoveryPolicyHash: recoveryPolicyHash,
            registeredAt: uint64(block.timestamp)
        });
        _deviceIds.push(deviceId);
        emit DeviceRegistered(
            deviceId,
            manufacturerName,
            model,
            hardwareRevision,
            firmwareVersion,
            firmwareHash,
            supportEndDate,
            recoveryPolicyHash,
            uint64(block.timestamp)
        );
        emit FirmwareRecorded(
            deviceId,
            firmwareVersion,
            firmwareHash,
            msg.sender,
            uint64(block.timestamp)
        );
    }

    function recordSupportEndDate(
        string calldata deviceId,
        uint64 supportEndDate
    ) external whenNotPaused deviceExists(deviceId) {
        require(
            msg.sender == administrator
                || (
                    manufacturers[msg.sender]
                        && devices[deviceId].manufacturerAccount == msg.sender
                ),
            "manufacturer/admin only"
        );
        devices[deviceId].supportEndDate = supportEndDate;
        emit SupportEndDateRecorded(deviceId, supportEndDate, msg.sender, uint64(block.timestamp));
    }

    function proposeOrphanDecision(
        string calldata deviceId,
        bool decision,
        bytes32 evidenceHash
    ) external whenNotPaused deviceExists(deviceId) {
        require(reviewers[msg.sender] || msg.sender == administrator, "verifier role required");
        require(evidenceHash != bytes32(0), "evidence hash required");
        OrphanProposal storage proposal = orphanProposals[deviceId];
        require(!proposal.exists || proposal.finalized, "decision already pending");
        proposal.exists = true;
        proposal.decision = decision;
        proposal.submittedAt = uint64(block.timestamp);
        proposal.proposalId = ++_proposalNonce;
        proposal.evidenceHash = evidenceHash;
        proposal.approvals = 0;
        proposal.rejections = 0;
        proposal.finalized = false;
        emit OrphanDecisionProposed(deviceId, decision, evidenceHash, uint64(block.timestamp));
    }

    function voteOrphanDecision(
        string calldata deviceId,
        bool approval
    ) external whenNotPaused deviceExists(deviceId) {
        OrphanProposal storage proposal = orphanProposals[deviceId];
        require(proposal.exists && !proposal.finalized, "no pending orphan decision");
        require(_isAssignedReviewer(deviceId, msg.sender), "assigned reviewer only");
        bytes32 voteKey = keccak256(
            abi.encodePacked("ORPHAN", deviceId, proposal.proposalId, msg.sender)
        );
        require(_voteMarkers[voteKey] == 0, "reviewer already voted");
        _voteMarkers[voteKey] = approval ? 1 : 2;
        if (approval) proposal.approvals++;
        else proposal.rejections++;
        emit OrphanDecisionVoted(deviceId, msg.sender, approval, uint64(block.timestamp));
    }

    mapping(bytes32 => uint8) private _voteMarkers;

    function finalizeOrphanDecision(
        string calldata deviceId
    ) external whenNotPaused deviceExists(deviceId) {
        OrphanProposal storage proposal = orphanProposals[deviceId];
        require(proposal.exists && !proposal.finalized, "no pending orphan decision");
        require(
            block.timestamp >= proposal.submittedAt + ORPHAN_CHALLENGE_PERIOD,
            "challenge period active"
        );
        require(
            proposal.approvals >= REQUIRED_APPROVALS || proposal.rejections >= REQUIRED_APPROVALS,
            "reviewer threshold not met"
        );
        proposal.finalized = true;
        bool verified = proposal.decision && proposal.approvals >= REQUIRED_APPROVALS;
        devices[deviceId].orphanVerified = verified;
        if (!verified) {
            string memory authorizedPatch = recoveryPatch[deviceId];
            if (bytes(authorizedPatch).length > 0) {
                delete recoveryPatch[deviceId];
                emit RecoveryRevoked(
                    deviceId,
                    authorizedPatch,
                    msg.sender,
                    uint64(block.timestamp)
                );
            }
        }
        emit OrphanDecisionFinalized(
            deviceId,
            verified,
            proposal.approvals,
            proposal.rejections,
            uint64(block.timestamp)
        );
    }

    function proposeMaintainer(
        string calldata deviceId,
        address maintainer
    ) external deviceExists(deviceId) onlyAdministrator {
        require(maintainer != address(0), "invalid maintainer");
        require(!maintainers[deviceId][maintainer], "already authorized");
        MaintainerProposal storage proposal = maintainerProposals[deviceId][maintainer];
        require(!proposal.exists || proposal.finalized, "maintainer proposal exists");
        proposal.exists = true;
        proposal.finalized = false;
        proposal.proposalId = ++_proposalNonce;
        proposal.approvals = 0;
        proposal.rejections = 0;
        proposal.proposedAt = uint64(block.timestamp);
        emit MaintainerProposed(deviceId, maintainer, uint64(block.timestamp));
    }

    function voteMaintainer(
        string calldata deviceId,
        address maintainer,
        bool approval
    ) external whenNotPaused deviceExists(deviceId) {
        require(_isAssignedReviewer(deviceId, msg.sender), "assigned reviewer only");
        MaintainerProposal storage proposal = maintainerProposals[deviceId][maintainer];
        require(proposal.exists && !proposal.finalized, "no pending maintainer proposal");
        bytes32 voteKey = keccak256(
            abi.encodePacked("MAINTAINER", deviceId, maintainer, proposal.proposalId, msg.sender)
        );
        require(_voteMarkers[voteKey] == 0, "reviewer already voted");
        _voteMarkers[voteKey] = approval ? 1 : 2;
        if (approval) proposal.approvals++;
        else proposal.rejections++;
        emit MaintainerVoted(deviceId, maintainer, msg.sender, approval, uint64(block.timestamp));
        if (proposal.approvals >= REQUIRED_APPROVALS) {
            proposal.finalized = true;
            maintainers[deviceId][maintainer] = true;
            emit MaintainerAuthorized(deviceId, maintainer, uint64(block.timestamp));
        } else if (proposal.rejections >= REQUIRED_APPROVALS) {
            proposal.finalized = true;
        }
    }

    function revokeMaintainer(
        string calldata deviceId,
        address maintainer
    ) external deviceExists(deviceId) onlyAdministrator {
        require(maintainers[deviceId][maintainer], "maintainer not authorized");
        maintainers[deviceId][maintainer] = false;
        string memory patchId = recoveryPatch[deviceId];
        if (bytes(patchId).length > 0) {
            delete recoveryPatch[deviceId];
            emit RecoveryRevoked(deviceId, patchId, msg.sender, uint64(block.timestamp));
        }
        emit MaintainerRevoked(deviceId, maintainer, msg.sender, uint64(block.timestamp));
    }

    function submitPatch(
        string calldata deviceId,
        string calldata patchId,
        bytes32 firmwareHash,
        bool automatedTestsPassed
    ) external whenNotPaused deviceExists(deviceId) {
        require(researchers[msg.sender] || msg.sender == administrator, "researcher/admin only");
        require(devices[deviceId].orphanVerified, "orphan verification required");
        require(bytes(patchId).length > 0 && !patches[patchId].exists, "invalid or duplicate patch");
        require(firmwareHash != bytes32(0), "firmware hash required");
        patches[patchId] = PatchRecord({
            exists: true,
            automatedTestsPassed: automatedTestsPassed,
            approved: false,
            reviewFinalized: false,
            patchHash: firmwareHash,
            approvals: 0,
            rejections: 0,
            submitter: msg.sender
        });
        devicePatchIds[deviceId].push(patchId);
        emit PatchSubmitted(
            deviceId,
            patchId,
            firmwareHash,
            automatedTestsPassed,
            msg.sender,
            uint64(block.timestamp)
        );
    }

    function votePatch(
        string calldata patchId,
        bool approval
    ) external whenNotPaused {
        PatchRecord storage patch = patches[patchId];
        require(patch.exists, "unknown patch");
        require(patch.automatedTestsPassed, "automated tests must pass");
        require(!patch.reviewFinalized, "patch review finalized");
        require(reviewers[msg.sender], "reviewer role required");
        string memory deviceId = _patchDevice(patchId);
        require(_isAssignedReviewer(deviceId, msg.sender), "assigned reviewer only");
        bytes32 voteKey = keccak256(abi.encodePacked("PATCH", patchId, msg.sender));
        require(_voteMarkers[voteKey] == 0, "reviewer already voted");
        _voteMarkers[voteKey] = approval ? 1 : 2;
        if (approval) patch.approvals++;
        else patch.rejections++;
        emit PatchApprovalVoted(patchId, msg.sender, approval, uint64(block.timestamp));
        if (patch.approvals >= REQUIRED_APPROVALS) {
            patch.approved = true;
            patch.reviewFinalized = true;
            emit PatchApprovalFinalized(patchId, true, patch.approvals, patch.rejections, uint64(block.timestamp));
        } else if (patch.rejections >= REQUIRED_APPROVALS) {
            patch.reviewFinalized = true;
            emit PatchApprovalFinalized(patchId, false, patch.approvals, patch.rejections, uint64(block.timestamp));
        }
    }

    function authorizeRecovery(
        string calldata deviceId,
        string calldata patchId
    ) external whenNotPaused deviceExists(deviceId) onlyAdministrator {
        PatchRecord storage patch = patches[patchId];
        require(patch.exists && patch.approved, "patch approval required");
        require(
            keccak256(bytes(_patchDevice(patchId))) == keccak256(bytes(deviceId)),
            "patch belongs to another device"
        );
        require(devices[deviceId].orphanVerified, "orphan verification required");
        recoveryPatch[deviceId] = patchId;
        emit RecoveryAuthorized(deviceId, patchId, msg.sender, uint64(block.timestamp));
    }

    function recordFirmwareRelease(
        string calldata deviceId,
        string calldata patchId,
        string calldata firmwareVersion,
        bytes32 actualFirmwareHash
    ) external whenNotPaused deviceExists(deviceId) {
        require(maintainers[deviceId][msg.sender], "authorized community maintainer only");
        require(devices[deviceId].orphanVerified, "orphan verification required");
        require(keccak256(bytes(recoveryPatch[deviceId])) == keccak256(bytes(patchId)), "recovery authorization required");
        PatchRecord storage patch = patches[patchId];
        require(patch.approved && patch.automatedTestsPassed, "approved patch required");
        require(actualFirmwareHash == patch.patchHash, "firmware hash mismatch");
        require(bytes(firmwareVersion).length > 0, "firmware version required");
        devices[deviceId].firmwareVersion = firmwareVersion;
        devices[deviceId].firmwareHash = actualFirmwareHash;
        emit FirmwareRecorded(
            deviceId,
            firmwareVersion,
            actualFirmwareHash,
            msg.sender,
            uint64(block.timestamp)
        );
        emit FirmwareReleased(
            deviceId,
            patchId,
            firmwareVersion,
            actualFirmwareHash,
            msg.sender,
            uint64(block.timestamp)
        );
    }

    function revokeRecovery(
        string calldata deviceId
    ) external deviceExists(deviceId) onlyAdministrator {
        string memory patchId = recoveryPatch[deviceId];
        require(bytes(patchId).length > 0, "no recovery authorization");
        delete recoveryPatch[deviceId];
        emit RecoveryRevoked(deviceId, patchId, msg.sender, uint64(block.timestamp));
    }

    function pause() external onlyAdministrator {
        require(!paused, "already paused");
        paused = true;
        emit EmergencyPause(true, msg.sender, uint64(block.timestamp));
    }

    function unpause() external onlyAdministrator {
        require(paused, "not paused");
        paused = false;
        emit EmergencyPause(false, msg.sender, uint64(block.timestamp));
    }

    function getDevice(string calldata deviceId) external view returns (Device memory) {
        require(devices[deviceId].exists, "unknown device");
        return devices[deviceId];
    }

    function getDeviceReviewers(string calldata deviceId) external view returns (address[] memory) {
        require(devices[deviceId].exists, "unknown device");
        return deviceReviewers[deviceId];
    }

    function getDevicePatchIds(string calldata deviceId) external view returns (string[] memory) {
        require(devices[deviceId].exists, "unknown device");
        return devicePatchIds[deviceId];
    }

    function _isAssignedReviewer(string memory deviceId, address account) private view returns (bool) {
        if (!reviewers[account]) return false;
        address[] storage assigned = deviceReviewers[deviceId];
        for (uint256 i = 0; i < assigned.length; i++) {
            if (assigned[i] == account) return true;
        }
        return false;
    }

    function _patchDevice(string memory patchId) private view returns (string memory) {
        for (uint256 i = 0; i < _deviceIds.length; i++) {
            string[] storage ids = devicePatchIds[_deviceIds[i]];
            for (uint256 j = 0; j < ids.length; j++) {
                if (keccak256(bytes(ids[j])) == keccak256(bytes(patchId))) {
                    return _deviceIds[i];
                }
            }
        }
        revert("patch device not found");
    }

    string[] private _deviceIds;
}
