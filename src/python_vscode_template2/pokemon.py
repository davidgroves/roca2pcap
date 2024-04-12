"""An example pokemon library to demo async testing"""

import collections.abc

import httpx


async def get_pokemon_names(start: int, end: int) -> collections.abc.AsyncGenerator[str, None]:
    """A generator of all pokemon names in the given range of pokemon ids

    Args:
        start (int): The lowest pokemon id to fetch.
        end (int): The highest pokemon id to fetch.

    Yields:
        str: A pokemon name

    Note, it is really hard to write doctests for async functions at this time.
    """

    client = httpx.AsyncClient()
    for i in range(start, end + 1):
        resp = await client.get(f"https://pokeapi.co/api/v2/pokemon/{i}/")
        yield resp.json()["name"]

    await client.aclose()
