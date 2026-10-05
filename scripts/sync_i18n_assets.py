"""
MkDocs hook: Sync static assets to secondary i18n locales.

mkdocs-static-i18n builds the default language (ko) to the site root (site/)
and secondary languages (en) to subdirectories (site/en/).
Static assets in docs/assets/ are copied by MkDocs to site/assets/,
leaving site/en/assets/ empty and causing relative links like
../../assets/diagrams/... from English pages to return 404 Not Found.

This hook runs on post_build (after mkdocs-static-i18n finishes building)
and synchronizes site/assets/ into site/en/assets/, ensuring all diagrams,
images, and stylesheets load seamlessly across all languages.
"""

from pathlib import Path
import shutil
from mkdocs.plugins import event_priority, get_plugin_logger

log = get_plugin_logger("sync_i18n_assets")


@event_priority(-200)
def on_post_build(config):
    site_dir = Path(config["site_dir"])
    assets_src = site_dir / "assets"

    if not assets_src.exists():
        return

    # Secondary languages to sync assets into
    locales = ["en"]
    for locale in locales:
        locale_assets_dest = site_dir / locale / "assets"
        log.info(f"Syncing static assets from {assets_src} to {locale_assets_dest}")
        shutil.copytree(assets_src, locale_assets_dest, dirs_exist_ok=True)
