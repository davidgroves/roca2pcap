import pytest

import python_vscode_template2.pokemon


@pytest.mark.asyncio
async def test_get_first_three_pokemon():
    names = []
    async for name in python_vscode_template2.pokemon.get_pokemon_names(start=1, end=3):
        names.append(name)
    assert names == ["bulbasaur", "ivysaur", "venusaur"]
