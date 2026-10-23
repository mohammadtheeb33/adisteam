"""Framework errors use the ADIS error envelope."""

from tests.unit.api.fakes import AUTH, api_client


def test_unknown_routes_are_not_found() -> None:
    with api_client() as (client, _):
        response = client.get("/api/v1/unknown", headers={"X-Request-ID": "r-404"})

    assert response.status_code == 404
    assert response.json() == {
        "error": {
            "code": "not_found",
            "message": "Not Found",
            "request_id": "r-404",
            "details": [],
        }
    }


def test_wrong_methods_are_not_allowed() -> None:
    with api_client() as (client, _):
        response = client.get("/api/v1/events", headers=AUTH)

    assert response.status_code == 405
    assert response.json()["error"]["code"] == "method_not_allowed"
    assert "POST" in response.headers["Allow"]
