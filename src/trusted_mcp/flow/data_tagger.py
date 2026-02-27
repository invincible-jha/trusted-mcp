"""Data origin tagging and lineage tracking across MCP servers.

When data flows from one MCP server to another (e.g., the output of
server A's tool becomes the input to server B's tool), this module
tracks that lineage so the flow analyser can detect cross-boundary
information leakage.

Design
------
- Each piece of data gets a DataTag recording the origin server and
  the tool that produced it.
- Tags propagate through the call chain as a lineage list.
- The tagger is stateless beyond the in-memory tag store; callers
  control the session scope by creating a new DataTagger per session.
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class TrustLevel(str, Enum):
    """Trust level assigned to a data origin server.

    Maps to the zone model used in enterprise network segmentation.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class DataTag:
    """Immutable tag recording the origin of a piece of data.

    Attributes
    ----------
    origin_server:
        The MCP server name that produced this data.
    origin_tool:
        The tool name that produced this data.
    trust_level:
        The trust level of the origin server at the time of tagging.
    tag_id:
        Unique identifier for this tag (auto-generated UUID).
    content_hash:
        SHA-256 hex digest of the tagged content for integrity tracking.
    lineage:
        Ordered list of (server_name, tool_name) pairs representing the
        chain of servers that have touched or transformed this data.
    """

    origin_server: str
    origin_tool: str
    trust_level: TrustLevel = TrustLevel.MEDIUM
    tag_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    content_hash: str = ""
    lineage: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def with_hop(self, server_name: str, tool_name: str) -> "DataTag":
        """Return a new DataTag with an additional lineage hop appended.

        Parameters
        ----------
        server_name:
            The server that processed or forwarded this data.
        tool_name:
            The tool within that server that processed the data.

        Returns
        -------
        DataTag
            New immutable tag with the hop recorded in lineage.
        """
        new_lineage = self.lineage + ((server_name, tool_name),)
        return DataTag(
            origin_server=self.origin_server,
            origin_tool=self.origin_tool,
            trust_level=self.trust_level,
            tag_id=self.tag_id,
            content_hash=self.content_hash,
            lineage=new_lineage,
        )

    @property
    def hop_count(self) -> int:
        """Number of additional servers this data has passed through."""
        return len(self.lineage)

    @property
    def has_crossed_boundary(self) -> bool:
        """True if the data has moved beyond its origin server."""
        for server_name, _ in self.lineage:
            if server_name != self.origin_server:
                return True
        return False

    def servers_in_lineage(self) -> set[str]:
        """Return the set of all server names that have seen this data.

        Returns
        -------
        set[str]
            Includes the origin server plus all servers in the lineage.
        """
        servers = {self.origin_server}
        for server_name, _ in self.lineage:
            servers.add(server_name)
        return servers


@dataclass
class TaggedData:
    """A piece of data paired with its provenance tag.

    Attributes
    ----------
    content:
        The raw data content (string, dict, or list as returned by MCP).
    tag:
        The DataTag recording where this data originated.
    """

    content: object
    tag: DataTag

    @classmethod
    def create(
        cls,
        content: object,
        origin_server: str,
        origin_tool: str,
        trust_level: TrustLevel = TrustLevel.MEDIUM,
    ) -> "TaggedData":
        """Factory: create TaggedData with a freshly minted DataTag.

        Parameters
        ----------
        content:
            The data payload to tag.
        origin_server:
            The MCP server that produced this data.
        origin_tool:
            The tool that produced this data.
        trust_level:
            Trust level of the origin server.

        Returns
        -------
        TaggedData
        """
        content_str = str(content)
        content_hash = hashlib.sha256(content_str.encode("utf-8")).hexdigest()[:16]

        tag = DataTag(
            origin_server=origin_server,
            origin_tool=origin_tool,
            trust_level=trust_level,
            content_hash=content_hash,
        )
        return cls(content=content, tag=tag)

    def forwarded_to(self, server_name: str, tool_name: str) -> "TaggedData":
        """Return a new TaggedData recording a forward to another server/tool.

        Parameters
        ----------
        server_name:
            The server receiving this data.
        tool_name:
            The tool receiving this data.

        Returns
        -------
        TaggedData
            New instance with updated lineage tag; original is unchanged.
        """
        new_tag = self.tag.with_hop(server_name, tool_name)
        return TaggedData(content=self.content, tag=new_tag)


class DataTagger:
    """Session-scoped registry that tags data and tracks its lineage.

    Usage
    -----
    ::

        tagger = DataTagger()
        tagged = tagger.tag(response_content, "server_a", "read_file")
        # Later, when used by server_b:
        forwarded = tagger.forward(tagged, "server_b", "process_data")
        print(forwarded.tag.has_crossed_boundary)  # True

    The tagger maintains an internal index of all tagged data keyed by
    tag_id, enabling lineage queries across the session.
    """

    def __init__(
        self,
        server_trust_map: dict[str, TrustLevel] | None = None,
    ) -> None:
        """Initialise the tagger.

        Parameters
        ----------
        server_trust_map:
            Optional mapping of server_name -> TrustLevel.
            If not provided, all servers default to MEDIUM.
        """
        self._server_trust_map: dict[str, TrustLevel] = server_trust_map or {}
        self._registry: dict[str, TaggedData] = {}

    def set_trust_level(self, server_name: str, trust_level: TrustLevel) -> None:
        """Assign a trust level to a server.

        Parameters
        ----------
        server_name:
            The MCP server name.
        trust_level:
            Trust level to assign.
        """
        self._server_trust_map[server_name] = trust_level

    def trust_level_for(self, server_name: str) -> TrustLevel:
        """Look up the trust level for a server.

        Parameters
        ----------
        server_name:
            The MCP server name.

        Returns
        -------
        TrustLevel
            Configured trust level, or MEDIUM if not configured.
        """
        return self._server_trust_map.get(server_name, TrustLevel.MEDIUM)

    def tag(
        self,
        content: object,
        server_name: str,
        tool_name: str,
    ) -> TaggedData:
        """Tag fresh data with its origin and register it.

        Parameters
        ----------
        content:
            The data to tag.
        server_name:
            The origin MCP server.
        tool_name:
            The origin tool.

        Returns
        -------
        TaggedData
            Tagged data record registered in the internal index.
        """
        trust_level = self.trust_level_for(server_name)
        tagged = TaggedData.create(
            content=content,
            origin_server=server_name,
            origin_tool=tool_name,
            trust_level=trust_level,
        )
        self._registry[tagged.tag.tag_id] = tagged
        logger.debug(
            "Tagged data from server=%r tool=%r tag_id=%s",
            server_name,
            tool_name,
            tagged.tag.tag_id,
        )
        return tagged

    def forward(
        self,
        tagged_data: TaggedData,
        receiving_server: str,
        receiving_tool: str,
    ) -> TaggedData:
        """Record that tagged data is being forwarded to another server.

        Parameters
        ----------
        tagged_data:
            The previously tagged data being forwarded.
        receiving_server:
            The server receiving the data.
        receiving_tool:
            The tool receiving the data.

        Returns
        -------
        TaggedData
            Updated TaggedData with extended lineage; the original is
            also updated in the registry.
        """
        forwarded = tagged_data.forwarded_to(receiving_server, receiving_tool)
        self._registry[forwarded.tag.tag_id] = forwarded
        logger.debug(
            "Forwarded tag_id=%s to server=%r tool=%r",
            forwarded.tag.tag_id,
            receiving_server,
            receiving_tool,
        )
        return forwarded

    def get(self, tag_id: str) -> TaggedData | None:
        """Retrieve a tagged data record by tag ID.

        Parameters
        ----------
        tag_id:
            The UUID string of the tag.

        Returns
        -------
        TaggedData | None
        """
        return self._registry.get(tag_id)

    def all_tags(self) -> list[DataTag]:
        """Return all tags registered in this session.

        Returns
        -------
        list[DataTag]
        """
        return [td.tag for td in self._registry.values()]

    def tags_from_server(self, server_name: str) -> list[DataTag]:
        """Return all tags whose origin is *server_name*.

        Parameters
        ----------
        server_name:
            Filter by this origin server.

        Returns
        -------
        list[DataTag]
        """
        return [
            td.tag
            for td in self._registry.values()
            if td.tag.origin_server == server_name
        ]

    def cross_boundary_tags(self) -> list[DataTag]:
        """Return all tags that have crossed server boundaries.

        Returns
        -------
        list[DataTag]
        """
        return [
            td.tag
            for td in self._registry.values()
            if td.tag.has_crossed_boundary
        ]
