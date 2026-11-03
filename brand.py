"""NextCore BD brand assets: the OSINT Hub logo (a purple tile with a magnifier that holds a small
link graph) and the brand colours. One source, used by the pages, the favicon and /logo.svg."""

PURPLE = "#7c3aed"        # buttons and the logo tile
PURPLE_DARK = "#6d28d9"   # button hover
PURPLE_LIGHT = "#a78bfa"  # links and highlights on dark backgrounds

_TILE = (
    '<defs><linearGradient id="nc-g" x1="0" y1="0" x2="1" y2="1">'
    '<stop offset="0" stop-color="#8b5cf6"/><stop offset="1" stop-color="#5b21b6"/></linearGradient></defs>'
    '<rect width="64" height="64" rx="16" fill="url(#nc-g)"/>'
    '<circle cx="28" cy="28" r="13" fill="none" stroke="#fff" stroke-width="4.5"/>'
    '<path d="M38 38 L50 50" stroke="#fff" stroke-width="6" stroke-linecap="round"/>'
    '<path d="M22 30 L32 22 L33 34 Z" fill="none" stroke="#fff" stroke-width="1.6" stroke-linejoin="round" opacity=".9"/>'
    '<circle cx="22" cy="30" r="2.8" fill="#fff"/><circle cx="32" cy="22" r="2.8" fill="#fff"/>'
    '<circle cx="33" cy="34" r="2.8" fill="#fff"/>'
)


def mark(size: int = 28, decorative: bool = True) -> str:
    """Inline SVG of the logo tile. `decorative` hides it from screen readers when a name sits next to it."""
    aria = 'aria-hidden="true"' if decorative else 'role="img" aria-label="OSINT Hub logo"'
    return (f'<svg class="mark" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="{size}" '
            f'height="{size}" {aria}>{_TILE}</svg>')


def favicon_svg() -> str:
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">{_TILE}</svg>'


def logo_svg(brand: str = "NextCore BD") -> str:
    """Horizontal lockup: tile, brand name and product name."""
    safe = brand.replace("&", "&amp;").replace("<", "&lt;")
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 360 64" width="360" height="64" role="img" '
        f'aria-label="{safe} OSINT Hub">'
        f'{_TILE}'
        f'<text x="80" y="30" font-family="system-ui,Segoe UI,Arial,sans-serif" font-size="22" font-weight="700" '
        f'fill="#7c3aed">{safe}</text>'
        '<text x="80" y="52" font-family="system-ui,Segoe UI,Arial,sans-serif" font-size="17" font-weight="500" '
        'fill="#6b7280" letter-spacing="2">OSINT HUB</text></svg>')
