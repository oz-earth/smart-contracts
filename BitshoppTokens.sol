// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import './ERC1155/ERC1155.sol';
import '@openzeppelin/contracts/security/Pausable.sol';
import '@openzeppelin/contracts/access/AccessControlEnumerable.sol';
import '@openzeppelin/contracts/utils/Context.sol';

import '@openzeppelin/contracts/utils/math/SafeMath.sol';
import '@openzeppelin/contracts/utils/Counters.sol';
import '@openzeppelin/contracts/utils/Strings.sol';
import '@openzeppelin/contracts/security/ReentrancyGuard.sol';

contract BitshoppTokens is
    Context,
    Pausable,
    ReentrancyGuard,
    AccessControlEnumerable,
    ERC1155
{
    using SafeMath for uint256;
    using Counters for Counters.Counter;

    bytes32 public constant MINTER_ROLE = keccak256('MINTER_ROLE');
    bytes32 public constant PAUSER_ROLE = keccak256('PAUSER_ROLE');
    bytes32 public constant TENANT_ROLE = keccak256('TENANT_ROLE');

    constructor(string memory _uri) ERC1155(_uri) {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());

        _setupRole(MINTER_ROLE, _msgSender());
        _setupRole(PAUSER_ROLE, _msgSender());
    }

    Counters.Counter private _tokenIdCounter;
    Counters.Counter private _projectIdCounter;

    mapping(uint256 => Token) private _idToToken;
    mapping(uint256 => Project) private _idToProject;

    event Trade();

    event TenantCreated(address indexed owner);

    event ProjectCreated(
        address indexed owner,
        uint256 indexed id,
        Project project
    );

    event TokenLocked(uint256 indexed id, Token token);

    event MintSingle(
        address indexed owner,
        address indexed to,
        uint256 indexed projectId,
        Token token
    );
    event MintBatch(
        address indexed owner,
        address indexed to,
        uint256 indexed projectId,
        Token[] token
    );

    enum TokenType {
        Fungible,
        NonFungible,
        SemiFungible
    }

    struct Token {
        address minter;
        uint256 id;
        uint256 projectId;
        uint256 maxSupply;
        uint256 totalSupply;
        uint256 burned;
        TokenType tokenType;
        bytes32 metadataHash;
        bool locked;
    }

    struct Project {
        uint256 id;
        address minter;
        TokenType tokenType;
    }

    function checkProjectOwner(uint256 projectId) internal view {
        require(
            _idToProject[projectId].minter == _msgSender(),
            'BitshoppTokens: sender is not project owner'
        );
    }

    modifier onlyProjectOwner(uint256 projectId) {
        checkProjectOwner(projectId);
        _;
    }

    function getToken(uint256 tokenId) external view returns (Token memory) {
        return _idToToken[tokenId];
    }

    function getProject(uint256 projectId)
        external
        view
        returns (Project memory)
    {
        return _idToProject[projectId];
    }

    function createTenant(address owner)
        external
        whenNotPaused
        onlyRole(DEFAULT_ADMIN_ROLE)
        returns (address)
    {
        require(
            !hasRole(TENANT_ROLE, owner),
            'BitshoppTokens: address already registered as sideA tenant'
        );
        _setupRole(TENANT_ROLE, owner);

        emit TenantCreated(owner);
        return owner;
    }

    function createProject(TokenType tokenType)
        external
        whenNotPaused
        onlyRole(TENANT_ROLE)
        returns (uint256)
    {
        uint256 projectId = incrementAndGet(_projectIdCounter);

        Project memory project = Project(projectId, _msgSender(), tokenType);

        _idToProject[projectId] = project;

        emit ProjectCreated(_msgSender(), projectId, project);

        return projectId;
    }

    function lockToken(uint256 tokenId, uint256 maxSupply)
        external
        whenNotPaused
        onlyRole(TENANT_ROLE)
        returns (Token memory)
    {
        Token storage token = _idToToken[tokenId];
        require(
            token.minter == _msgSender(),
            'BitshoppTokens: trying to lock token without being owner'
        );
        require(
            token.id != 0,
            "BitshoppTokens: trying to lock token that doesn't exist"
        );
        require(
            !token.locked,
            "BitshoppTokens: trying to lock token that's already locked"
        );

        require(
            maxSupply >= token.totalSupply + token.burned,
            'BitshoppTokens: maxSupply smaller than totalSupply'
        );

        token.maxSupply = maxSupply;
        token.locked = true;

        emit TokenLocked(token.id, token);
        return token;
    }

    function mint(
        address to,
        uint256 amount,
        uint256 maxSupply,
        bytes32 metadataHash,
        bool locked,
        uint256 projectId,
        bytes memory data
    )
        external
        whenNotPaused
        onlyRole(TENANT_ROLE)
        onlyProjectOwner(projectId)
        returns (uint256)
    {
        uint256 tokenId = incrementAndGet(_tokenIdCounter);
        address owner = _msgSender();

        require(
            projectId > 0 || projectId <= _projectIdCounter.current(),
            "BitshoppTokens: trying to use projectId that doesn't exist"
        );

        Project memory project = _idToProject[projectId];

        if (project.tokenType == TokenType.NonFungible) {
            amount = 1;
            maxSupply = 1;
            locked = true;
        }

        if (locked == false) {
            maxSupply = 0;
        }

        Token memory token = Token(
            owner,
            tokenId,
            projectId,
            maxSupply,
            0,
            0,
            project.tokenType,
            metadataHash,
            locked
        );

        _idToToken[token.id] = token;
        emit MintSingle(owner, to, projectId, token);
        _mint(to, token.id, amount, data);
        return token.id;
    }

    function mint(
        address to,
        uint256 tokenId,
        uint256 amount,
        bytes memory data
    ) external whenNotPaused onlyRole(TENANT_ROLE) returns (uint256) {
        require(
            tokenId > 0 || tokenId <= _tokenIdCounter.current(),
            "BitshoppTokens: trying to use tokenId that doesn't exist"
        );

        Token memory token = _idToToken[tokenId];
        checkProjectOwner(token.projectId);

        require(
            token.tokenType != TokenType.NonFungible,
            'BitshoppTokens: mint for non-fungible'
        );
        require(
            token.minter == _msgSender(),
            'BitshoppTokens: sender is not minter'
        );
        _mint(to, tokenId, amount, data);

        return tokenId;
    }

    function mintBatch(
        address to,
        uint256 size,
        uint256[] memory amounts,
        bytes32[] memory hashes,
        uint256 maxSupply,
        bool locked,
        uint256 projectId,
        bytes memory data
    )
        public
        whenNotPaused
        onlyRole(TENANT_ROLE)
        onlyProjectOwner(projectId)
        returns (uint256[] memory, uint256[] memory)
    {
        require(size > 0, "BitshoppTokens: size can't be less then 1");
        require(
            size == amounts.length,
            'BitshoppTokens: size and amounts length mismatch'
        );
        require(
            amounts.length == hashes.length,
            'BitshoppTokens: amounts and hashes length mismatch'
        );

        require(
            projectId > 0 || projectId <= _projectIdCounter.current(),
            "BitshoppTokens: trying to use projectId that doesn't exist"
        );

        Project memory project = _idToProject[projectId];

        if (project.tokenType == TokenType.NonFungible) {
            maxSupply = 1;
            locked = true;
        }

        if (locked == false) {
            maxSupply = 0;
        }

        uint256[] memory ids = new uint256[](size);
        Token[] memory tokens = new Token[](size);

        {
            for (uint256 i = 0; i < size; i++) {
                ids[i] = incrementAndGet(_tokenIdCounter);

                if (project.tokenType == TokenType.NonFungible) {
                    amounts[i] = 1;
                }

                tokens[i] = Token(
                    _msgSender(),
                    ids[i],
                    projectId,
                    maxSupply,
                    0,
                    0,
                    project.tokenType,
                    hashes[i],
                    locked
                );
                _idToToken[ids[i]] = tokens[i];
            }
        }

        emit MintBatch(_msgSender(), to, projectId, tokens);
        _mintBatch(to, ids, amounts, data);

        return (ids, amounts);
    }

    function atomicSwaps(
        address[] memory from,
        address[] memory to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes[] memory data
    ) external nonReentrant whenNotPaused {
        require(
            from.length == to.length &&
                to.length == ids.length &&
                ids.length == amounts.length &&
                amounts.length == data.length,
            'BitshoppTokens: parameter arrays length mismatch'
        );

        for (uint256 i = 0; i < from.length; i++) {
            safeTransferFrom(from[i], to[i], ids[i], amounts[i], data[i]);
        }

        emit Trade();
    }

    function ownerOf(address account, uint256 id) external view returns (bool) {
        return balanceOf(account, id) > 0;
    }

    function setURI(string memory newuri)
        external
        whenNotPaused
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        _setURI(newuri);
    }

    function pause() external {
        require(
            hasRole(PAUSER_ROLE, _msgSender()),
            'BitshoppTokens: must have pauser role to pause'
        );
        _pause();
    }

    function unpause() external {
        require(
            hasRole(PAUSER_ROLE, _msgSender()),
            'BitshoppTokens: must have pauser role to unpause'
        );
        _unpause();
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControlEnumerable, ERC1155)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _afterTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual override(ERC1155) whenNotPaused {
        super._afterTokenTransfer(operator, from, to, ids, amounts, data);

        if (from == address(0)) {
            for (uint256 i = 0; i < ids.length; ++i) {
                uint256 amount = amounts[i];
                Token storage token = _idToToken[ids[i]];

                if (token.locked) {
                    require(
                        token.maxSupply >=
                            (token.totalSupply + token.burned + amount),
                        'BitshoppTokens: transfer exceeds max supply allowed'
                    );
                }
                token.totalSupply += amount;
            }
        }

        if (to == address(0)) {
            for (uint256 i = 0; i < ids.length; ++i) {
                uint256 amount = amounts[i];
                uint256 supply = _idToToken[ids[i]].totalSupply;
                require(
                    supply >= amount,
                    'ERC1155: burn amount exceeds totalSupply'
                );
                unchecked {
                    _idToToken[ids[i]].totalSupply = supply - amount;
                    _idToToken[ids[i]].burned += amount;
                }
            }
        }
    }

    function totalSupply(uint256 id) public view virtual returns (uint256) {
        return _idToToken[id].totalSupply;
    }

    function exists(uint256 id) external view virtual returns (bool) {
        return totalSupply(id) > 0;
    }

    function incrementAndGet(Counters.Counter storage counter)
        internal
        returns (uint256)
    {
        counter.increment();
        return counter.current();
    }

    function uri(uint256 id) public view override returns (string memory) {
        return string(abi.encodePacked(super.uri(id), Strings.toString(id)));
    }

    function burn(
        address from,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) external {
        require(
            from == _msgSender() || isApprovedForAll(from, _msgSender()),
            'BitshoppTokens: caller is not owner nor approved'
        );

        _burn(from, id, amount, data);
    }

    function burnBatch(
        address from,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) external {
        require(
            from == _msgSender() || isApprovedForAll(from, _msgSender()),
            'BitshoppTokens: caller is not owner nor approved'
        );

        _burnBatch(from, ids, amounts, data);
    }

    function balanceNFT(address account)
        external
        view
        returns (uint256[] memory, uint256[] memory)
    {
        uint256[] memory tokens = new uint256[](_tokenIdCounter.current());
        uint256[] memory balances = new uint256[](_tokenIdCounter.current());
        uint256 countResult = 0;

        for (uint256 id = 0; id <= _tokenIdCounter.current(); id++) {
            uint256 balance = balanceOf(account, id);

            if (balance > 0) {
                tokens[countResult] = id;
                balances[countResult] = balance;
                countResult++;
            }
        }

        return (tokens, balances);
    }
}
