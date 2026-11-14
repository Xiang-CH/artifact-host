"""Artifact-scoped browser resource policies and remembered-read context checks."""
from urllib.parse import quote


DENY_CSP = "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"


def resource_paths(row, alias=None):
    # Both URL forms stay within the same owning artifact.
    paths = ['/s/' + row['id'] + '/']
    if alias:
        paths.append('/' + alias + '/')
    return paths


def content_policy(origin, paths, resource_base=False):
    sources = ' '.join(origin + quote(path, safe='/') for path in paths)
    return ("sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline' " + sources
            + "; style-src 'unsafe-inline' " + sources + '; img-src data: ' + sources
            + '; font-src ' + sources
            + "; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri " + (sources if resource_base else "'none'")
            + "; form-action 'none'; frame-ancestors 'none'")


def remembered_read_context(headers):
    # HttpOnly protects the cookie value, not authenticated classic-script loads.
    # Fetch Metadata is browser-controlled. A top-level navigation may use its
    # cookie. Resource endpoints require a separate scoped grant, even if a
    # remembered cookie is automatically attached by the browser.
    return headers.get('Sec-Fetch-Dest') == 'document' and headers.get('Sec-Fetch-Mode') == 'navigate'
