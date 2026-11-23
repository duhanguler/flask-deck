from __future__ import annotations

from typing import TYPE_CHECKING

from flask import Blueprint

from flask_deck.routes.api import register_api_routes
from flask_deck.routes.auth import register_auth_routes
from flask_deck.routes.crud import register_crud_routes
from flask_deck.routes.governance import register_governance_routes
from flask_deck.routes.iam import register_iam_routes
from flask_deck.routes.jobs import register_job_routes
from flask_deck.routes.ops import register_ops_routes

if TYPE_CHECKING:
    from flask_deck.deck import Deck


def register_all_routes(bp: Blueprint, deck: Deck) -> None:
    """Register all Flask-Deck route groups on the blueprint preserving exact endpoints."""
    register_auth_routes(bp, deck)
    register_iam_routes(bp, deck)
    register_ops_routes(bp, deck)
    register_governance_routes(bp, deck)
    register_job_routes(bp, deck)
    register_api_routes(bp, deck)
    if deck.config.enable_rest_api:
        from flask_deck.rest_api import register_rest_api_routes

        register_rest_api_routes(bp, deck)
    if deck.config.enable_mcp:
        from flask_deck.mcp_server import register_mcp_routes

        register_mcp_routes(bp, deck)
    register_crud_routes(bp, deck)
