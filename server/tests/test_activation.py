from httpx import AsyncClient

from tests.conftest import URL, count_licenses, make_token


async def test_broken_ciphertext(client: AsyncClient) -> None:
    response = await client.post(URL, json={"payload": "not-base64"})

    assert response.status_code == 400
    assert response.json()["detail"] == "cannot decrypt payload"
    assert await count_licenses() == 0


async def test_invalid_license_format(client: AsyncClient) -> None:
    token = make_token(license="12345:1231213:123123:!23")

    response = await client.post(URL, json={"payload": token})

    assert response.status_code == 422
    assert await count_licenses() == 0


async def test_repeat_activation_is_idempotent(client: AsyncClient) -> None:
    token = make_token()

    first = await client.post(URL, json={"payload": token})
    second = await client.post(URL, json={"payload": token})

    assert first.status_code == 200
    assert first.json()["already_activated"] is False
    assert second.status_code == 200
    assert second.json()["already_activated"] is True
    assert second.json()["activation_id"] == first.json()["activation_id"]
    assert second.json()["activated_at"] == first.json()["activated_at"]
    assert await count_licenses() == 1


async def test_same_license_other_device(client: AsyncClient) -> None:
    await client.post(URL, json={"payload": make_token()})

    response = await client.post(URL, json={"payload": make_token(mac="aa:bb:cc:dd:ee:ff")})

    assert response.status_code == 409
    assert response.json()["detail"] == "license is already activated on another device"
    assert await count_licenses() == 1
